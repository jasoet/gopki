//go:build example

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jasoet/gopki/jose/jwe"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func main() {
	fmt.Println("=== GoPKI JWE Module - Comprehensive Examples ===")
	fmt.Println("Demonstrating JWE (JSON Web Encryption) functionality")
	fmt.Println()

	// Create outputs directory
	if err := os.MkdirAll("output", 0o755); err != nil {
		log.Fatal("Failed to create output directory:", err)
	}

	// Part 1: Compact Serialization
	fmt.Println("🔐 PART 1: Compact Serialization (Single Recipient)")
	fmt.Println(strings.Repeat("=", 70))
	compactEncryptionExample()

	// Part 2: JSON Serialization
	fmt.Println("\n🔐 PART 2: JSON Serialization")
	fmt.Println(strings.Repeat("=", 70))
	jsonSerializationExample()

	// Part 3: Multi-Recipient Encryption
	fmt.Println("\n👥 PART 3: Multi-Recipient Encryption")
	fmt.Println(strings.Repeat("=", 70))
	multiRecipientExample()

	// Part 4: Real-World Use Cases
	fmt.Println("\n🌐 PART 4: Real-World Use Cases")
	fmt.Println(strings.Repeat("=", 70))
	confidentialDocumentExample()
	teamCollaborationExample()

	fmt.Println("\n✅ All examples completed successfully!")
	fmt.Println("📁 Encrypted data saved to output/jwe_*.txt")
}

func compactEncryptionExample() {
	plaintext := []byte("This is a secret message that needs encryption")

	// RSA-OAEP-256 + A256GCM
	fmt.Println("\n🔒 RSA-OAEP-256 with A256GCM:")
	rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key:", err)
	}

	fmt.Printf("   Plaintext: %s\n", string(plaintext))
	fmt.Printf("   Algorithm: RSA-OAEP-256 (key) + A256GCM (content)\n")

	// Encrypt
	encrypted, err := jwe.EncryptCompact(
		plaintext,
		rsaKeys,
		"RSA-OAEP-256", // Key encryption algorithm
		"A256GCM",      // Content encryption algorithm
		"recipient-1",
	)
	if err != nil {
		log.Fatal("Failed to encrypt:", err)
	}

	fmt.Printf("   Encrypted: %s...\n", encrypted[:80])
	fmt.Printf("   Format: header.enckey.iv.ciphertext.tag (5 parts)\n")
	fmt.Printf("   Length: %d bytes\n", len(encrypted))

	// Save encrypted data
	os.WriteFile("output/jwe_compact_rsa.txt", []byte(encrypted), 0o644)

	// Decrypt
	fmt.Println("\n   Decrypting...")
	decrypted, err := jwe.DecryptCompact(encrypted, rsaKeys)
	if err != nil {
		log.Fatal("Failed to decrypt:", err)
	}

	fmt.Printf("   ✓ Decrypted: %s\n", string(decrypted))

	if string(decrypted) != string(plaintext) {
		log.Fatal("Decrypted text doesn't match original!")
	}
	fmt.Println("   ✓ Round-trip successful")
}

func jsonSerializationExample() {
	message := []byte("Confidential financial report for Q4 2024")

	fmt.Println("\n📄 JSON Serialization (Single Recipient):")
	rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	fmt.Printf("   Message: %s\n", string(message))

	// Encrypt in JSON format
	encrypted, err := jwe.EncryptJSON(
		message,
		[]keypair.GenericPublicKey{rsaKeys.PublicKey},
		"A256GCM",
		[]string{"RSA-OAEP-256"},
		[]string{"finance-dept-key"},
	)
	if err != nil {
		log.Fatal("Failed to encrypt JSON:", err)
	}

	fmt.Printf("   ✓ Encrypted for 1 recipient\n")

	// Marshal to JSON
	jsonBytes, err := encrypted.Marshal()
	if err != nil {
		log.Fatal("Failed to marshal JSON:", err)
	}

	fmt.Printf("   JSON size: %d bytes\n", len(jsonBytes))
	os.WriteFile("output/jwe_json_single.json", jsonBytes, 0o644)

	// Decrypt
	fmt.Println("\n   Decrypting...")
	decrypted, err := jwe.DecryptJSON(encrypted, rsaKeys)
	if err != nil {
		log.Fatal("Failed to decrypt JSON:", err)
	}

	fmt.Printf("   ✓ Decrypted: %s\n", string(decrypted))
}

func multiRecipientExample() {
	secret := []byte("Top secret project details: Project Falcon launch date is 2025-01-15")

	fmt.Println("\n👥 Multi-Recipient Encryption:")
	fmt.Println("   Scenario: Encrypt for 3 team members")

	// Generate keys for 3 recipients
	aliceKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	bobKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	carolKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	fmt.Println("\n   Recipient 1 - Alice (Project Lead)")
	fmt.Println("     Key: RSA 2048-bit")
	fmt.Println("\n   Recipient 2 - Bob (Tech Lead)")
	fmt.Println("     Key: RSA 2048-bit")
	fmt.Println("\n   Recipient 3 - Carol (Security Lead)")
	fmt.Println("     Key: RSA 2048-bit")

	recipients := []keypair.GenericPublicKey{
		aliceKeys.PublicKey,
		bobKeys.PublicKey,
		carolKeys.PublicKey,
	}

	keyAlgs := []string{"RSA-OAEP-256", "RSA-OAEP-256", "RSA-OAEP-256"}
	keyIDs := []string{"alice-project", "bob-tech", "carol-security"}

	// Encrypt for all recipients
	fmt.Println("\n   Encrypting for all 3 recipients...")
	encrypted, err := jwe.EncryptJSON(secret, recipients, "A256GCM", keyAlgs, keyIDs)
	if err != nil {
		log.Fatal("Failed to encrypt for multiple recipients:", err)
	}

	fmt.Printf("   ✓ Encrypted with %d recipient-specific keys\n", len(encrypted.Recipients))
	fmt.Println("   ✓ Same ciphertext, different encrypted keys")

	// Marshal
	jsonBytes, _ := encrypted.Marshal()
	fmt.Printf("   ✓ JSON size: %d bytes\n", len(jsonBytes))
	os.WriteFile("output/jwe_multi_recipient.json", jsonBytes, 0o644)

	// Each recipient can decrypt independently
	fmt.Println("\n   Decrypting with each recipient's key:")

	decrypted1, err := jwe.DecryptJSON(encrypted, aliceKeys)
	if err != nil {
		log.Fatal("Alice failed to decrypt:", err)
	}
	fmt.Printf("   ✓ Alice decrypted: %s...\n", string(decrypted1[:40]))

	decrypted2, err := jwe.DecryptJSON(encrypted, bobKeys)
	if err != nil {
		log.Fatal("Bob failed to decrypt:", err)
	}
	fmt.Printf("   ✓ Bob decrypted: %s...\n", string(decrypted2[:40]))

	decrypted3, err := jwe.DecryptJSON(encrypted, carolKeys)
	if err != nil {
		log.Fatal("Carol failed to decrypt:", err)
	}
	fmt.Printf("   ✓ Carol decrypted: %s...\n", string(decrypted3[:40]))

	// Verify all decrypted to same plaintext
	if string(decrypted1) == string(decrypted2) && string(decrypted2) == string(decrypted3) {
		fmt.Println("\n   ✅ All 3 recipients decrypted to same plaintext")
	}
}

func confidentialDocumentExample() {
	document := []byte(`
CONFIDENTIAL - DO NOT SHARE

Subject: Merger & Acquisition Proposal
Date: 2024-10-08

Company XYZ Corp is proposing acquisition of ABC Inc.
Terms:
- Purchase price: $500M
- Closing date: Q1 2025
- Employment retention: 95%

This information is highly confidential and restricted to:
- Board of Directors
- CFO
- Legal Counsel
`)

	fmt.Println("\n📋 Use Case: Confidential M&A Document")

	// Recipients: Board Chair, CFO, Legal Counsel
	boardChairKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	cfoKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	legalKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	fmt.Println("\n   Document: Merger & Acquisition Proposal")
	fmt.Println("   Classification: Highly Confidential")
	fmt.Println("   Recipients:")
	fmt.Println("   - Board Chair")
	fmt.Println("   - CFO")
	fmt.Println("   - Legal Counsel")

	recipients := []keypair.GenericPublicKey{
		boardChairKeys.PublicKey,
		cfoKeys.PublicKey,
		legalKeys.PublicKey,
	}

	keyAlgs := []string{"RSA-OAEP-256", "RSA-OAEP-256", "RSA-OAEP-256"}
	keyIDs := []string{"board-chair-2024", "cfo-2024", "legal-counsel-2024"}

	// Encrypt
	encrypted, _ := jwe.EncryptJSON(document, recipients, "A256GCM", keyAlgs, keyIDs)

	// Save
	jsonBytes, _ := json.MarshalIndent(encrypted, "", "  ")
	os.WriteFile("output/jwe_confidential_ma.json", jsonBytes, 0o644)

	fmt.Println("\n   ✓ Document encrypted for 3 authorized recipients")
	fmt.Println("   ✓ Saved to output/jwe_confidential_ma.json")

	// Simulate each recipient accessing the document
	fmt.Println("\n   Access Log:")

	// Board Chair
	decrypted, err := jwe.DecryptJSON(encrypted, boardChairKeys)
	if err == nil {
		fmt.Printf("   ✓ Board Chair accessed (document size: %d bytes)\n", len(decrypted))
	}

	// CFO
	decrypted, err = jwe.DecryptJSON(encrypted, cfoKeys)
	if err == nil {
		fmt.Printf("   ✓ CFO accessed (document size: %d bytes)\n", len(decrypted))
	}

	// Legal Counsel
	decrypted, err = jwe.DecryptJSON(encrypted, legalKeys)
	if err == nil {
		fmt.Printf("   ✓ Legal Counsel accessed (document size: %d bytes)\n", len(decrypted))
	}

	fmt.Println("\n   ✅ All authorized parties can access the confidential document")
}

func teamCollaborationExample() {
	sharedData := []byte(`
PROJECT FALCON - SPRINT PLANNING
Sprint: #42
Duration: 2024-10-14 to 2024-10-28

Team Members:
- Alice (Frontend): OAuth integration
- Bob (Backend): API v2 migration
- Carol (DevOps): K8s autoscaling
- Dave (QA): E2E test automation

Sprint Goal: Complete user authentication v2

API Keys (SENSITIVE):
- Staging: staging_api_key_xxxxxxxxxxxxxxxxxxxxx
- Auth0: auth0_dev_xxxxxxxxxxxxxxxxxxxxx

Database Credentials:
- Host: db.staging.internal
- User: app_falcon
- Pass: example_password_change_in_production
`)

	fmt.Println("\n👨‍💻 Use Case: Team Collaboration - Sprint Planning")

	// Team members
	aliceKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	bobKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	carolKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	daveKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	fmt.Println("\n   Document: Sprint Planning with Sensitive Credentials")
	fmt.Println("   Team:")
	fmt.Println("   - Alice (Frontend)")
	fmt.Println("   - Bob (Backend)")
	fmt.Println("   - Carol (DevOps)")
	fmt.Println("   - Dave (QA)")

	recipients := []keypair.GenericPublicKey{
		aliceKeys.PublicKey,
		bobKeys.PublicKey,
		carolKeys.PublicKey,
		daveKeys.PublicKey,
	}

	keyAlgs := []string{"RSA-OAEP-256", "RSA-OAEP-256", "RSA-OAEP-256", "RSA-OAEP-256"}
	keyIDs := []string{"alice-frontend", "bob-backend", "carol-devops", "dave-qa"}

	fmt.Println("\n   Encrypting sprint data for all team members...")
	encrypted, _ := jwe.EncryptJSON(sharedData, recipients, "A256GCM", keyAlgs, keyIDs)

	jsonBytes, _ := json.MarshalIndent(encrypted, "", "  ")
	os.WriteFile("output/jwe_team_sprint.json", jsonBytes, 0o644)

	fmt.Printf("   ✓ Encrypted for %d team members\n", len(recipients))
	fmt.Println("   ✓ Each member has their own encrypted key")
	fmt.Println("   ✓ Credentials protected with AES-256-GCM")

	// Simulate team accessing the document
	fmt.Println("\n   Team Access:")

	members := []struct {
		name string
		keys *algo.RSAKeyPair
	}{
		{"Alice", aliceKeys},
		{"Bob", bobKeys},
		{"Carol", carolKeys},
		{"Dave", daveKeys},
	}

	for _, member := range members {
		_, err := jwe.DecryptJSON(encrypted, member.keys)
		if err == nil {
			fmt.Printf("   ✓ %s accessed sprint data\n", member.name)
		}
	}

	fmt.Println("\n   Benefits:")
	fmt.Println("   - Each team member can decrypt independently")
	fmt.Println("   - If one member leaves, reencrypt excluding their key")
	fmt.Println("   - Audit trail via key IDs")
	fmt.Println("   - No shared passwords needed")
}
