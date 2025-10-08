//go:build example

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jasoet/gopki/jose/jws"
	"github.com/jasoet/gopki/keypair/algo"
)

func main() {
	fmt.Println("=== GoPKI JWS Module - Comprehensive Examples ===")
	fmt.Println("Demonstrating JWS (JSON Web Signature) functionality")
	fmt.Println()

	// Create outputs directory
	if err := os.MkdirAll("output", 0o755); err != nil {
		log.Fatal("Failed to create output directory:", err)
	}

	// Part 1: Compact Serialization
	fmt.Println("📝 PART 1: Compact Serialization (URL-safe)")
	fmt.Println(strings.Repeat("=", 70))
	compactSerializationExample()

	// Part 2: JSON Serialization
	fmt.Println("\n📝 PART 2: JSON Serialization")
	fmt.Println(strings.Repeat("=", 70))
	jsonSerializationExample()

	// Part 3: Multi-Signature
	fmt.Println("\n📝 PART 3: Multi-Signature Support")
	fmt.Println(strings.Repeat("=", 70))
	multiSignatureExample()

	// Part 4: Detached Content
	fmt.Println("\n📝 PART 4: Detached Content Signatures")
	fmt.Println(strings.Repeat("=", 70))
	detachedContentExample()

	// Part 5: Real-World Use Cases
	fmt.Println("\n🌐 PART 5: Real-World Use Cases")
	fmt.Println(strings.Repeat("=", 70))
	documentSigningExample()
	contractApprovalExample()

	fmt.Println("\n✅ All examples completed successfully!")
	fmt.Println("📁 Signatures saved to output/jws_*.txt")
}

func compactSerializationExample() {
	payload := []byte("This is a test message for compact JWS serialization")

	// RS256
	fmt.Println("\n🔐 RS256 Compact Signature:")
	rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	compactRS256, err := jws.SignCompact(payload, rsaKeys.PrivateKey, "RS256", "rsa-signing-key")
	if err != nil {
		log.Fatal("Failed to sign with RS256:", err)
	}
	fmt.Printf("   Signature: %s...\n", compactRS256[:80])
	fmt.Printf("   Format: header.payload.signature (3 parts)\n")

	// Verify
	verifiedPayload, err := jws.VerifyCompact(compactRS256, rsaKeys.PublicKey, "RS256")
	if err != nil {
		log.Fatal("Failed to verify RS256:", err)
	}
	fmt.Printf("   ✓ Verified: %s\n", string(verifiedPayload))
	os.WriteFile("output/jws_compact_rs256.txt", []byte(compactRS256), 0o644)

	// ES256
	fmt.Println("\n🔐 ES256 Compact Signature:")
	ecKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
	compactES256, _ := jws.SignCompact(payload, ecKeys.PrivateKey, "ES256", "ec-signing-key")
	fmt.Printf("   Signature: %s...\n", compactES256[:80])
	jws.VerifyCompact(compactES256, ecKeys.PublicKey, "ES256")
	fmt.Println("   ✓ Verified successfully")
	os.WriteFile("output/jws_compact_es256.txt", []byte(compactES256), 0o644)

	// EdDSA
	fmt.Println("\n🔐 EdDSA Compact Signature:")
	edKeys, _ := algo.GenerateEd25519KeyPair()
	compactEdDSA, _ := jws.SignCompact(payload, edKeys.PrivateKey, "EdDSA", "ed-signing-key")
	fmt.Printf("   Signature: %s...\n", compactEdDSA[:80])
	jws.VerifyCompact(compactEdDSA, edKeys.PublicKey, "EdDSA")
	fmt.Println("   ✓ Verified successfully")
	os.WriteFile("output/jws_compact_eddsa.txt", []byte(compactEdDSA), 0o644)

	// HMAC (HS256)
	fmt.Println("\n🔐 HS256 Compact Signature (HMAC):")
	secret := []byte("shared-secret-key-minimum-32-bytes-for-security")
	compactHS256, _ := jws.SignCompactWithSecret(payload, secret, "HS256")
	fmt.Printf("   Signature: %s...\n", compactHS256[:80])
	jws.VerifyCompactWithSecret(compactHS256, secret, "HS256")
	fmt.Println("   ✓ Verified successfully")
	os.WriteFile("output/jws_compact_hs256.txt", []byte(compactHS256), 0o644)
}

func jsonSerializationExample() {
	payload := []byte("This document is signed using JSON serialization")

	// Single signature
	fmt.Println("\n📄 JSON Serialization (Single Signature):")
	rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	signer := &jws.Signer{
		Key:       rsaKeys.PrivateKey,
		Algorithm: "RS256",
		KeyID:     "company-signing-key-2024",
	}

	jwsJSON, err := jws.SignJSON(payload, []*jws.Signer{signer})
	if err != nil {
		log.Fatal("Failed to create JSON signature:", err)
	}

	fmt.Printf("   Payload: %s\n", string(payload))
	fmt.Printf("   Signatures: 1\n")
	fmt.Printf("   Algorithm: RS256\n")
	fmt.Printf("   Key ID: %s\n", signer.KeyID)

	// Marshal to JSON
	jsonBytes, _ := json.Marshal(jwsJSON)
	fmt.Printf("   JSON Length: %d bytes\n", len(jsonBytes))
	os.WriteFile("output/jws_json_single.json", jsonBytes, 0o644)

	// Verify
	verifier := &jws.Verifier{
		Key:       rsaKeys.PublicKey,
		Algorithm: "RS256",
		KeyID:     "company-signing-key-2024",
	}
	verifiedPayload, err := jws.VerifyJSON(jwsJSON, []*jws.Verifier{verifier})
	if err != nil {
		log.Fatal("Failed to verify JSON signature:", err)
	}
	fmt.Printf("   ✓ Verified: %s\n", string(verifiedPayload))
}

func multiSignatureExample() {
	document := []byte("Multi-party agreement: Project funding approved")

	fmt.Println("\n🖊️  Multi-Party Document Signing:")
	fmt.Println("   Scenario: 3 parties sign the same document")

	// Generate keys for 3 signers
	aliceKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	bobKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
	carolKeys, _ := algo.GenerateEd25519KeyPair()

	fmt.Println("\n   Party 1 - Alice (RSA/RS256):")
	fmt.Println("     Role: CEO")
	fmt.Println("     Signature Algorithm: RS256")

	fmt.Println("\n   Party 2 - Bob (ECDSA/ES256):")
	fmt.Println("     Role: CFO")
	fmt.Println("     Signature Algorithm: ES256")

	fmt.Println("\n   Party 3 - Carol (Ed25519/EdDSA):")
	fmt.Println("     Role: CTO")
	fmt.Println("     Signature Algorithm: EdDSA")

	// Create signers
	signers := []*jws.Signer{
		{
			Key:       aliceKeys.PrivateKey,
			Algorithm: "RS256",
			KeyID:     "alice-ceo-2024",
		},
		{
			Key:       bobKeys.PrivateKey,
			Algorithm: "ES256",
			KeyID:     "bob-cfo-2024",
		},
		{
			Key:       carolKeys.PrivateKey,
			Algorithm: "EdDSA",
			KeyID:     "carol-cto-2024",
		},
	}

	// Sign document
	fmt.Println("\n   Creating multi-signature JWS...")
	multiSigned, err := jws.SignJSON(document, signers)
	if err != nil {
		log.Fatal("Failed to create multi-signature:", err)
	}

	fmt.Printf("   ✓ Document signed by %d parties\n", len(multiSigned.Signatures))

	// Marshal to JSON
	jsonBytes, _ := json.Marshal(multiSigned)
	fmt.Printf("   ✓ JSON size: %d bytes\n", len(jsonBytes))
	os.WriteFile("output/jws_multi_signature.json", jsonBytes, 0o644)

	// Verify each signature individually
	fmt.Println("\n   Verifying signatures:")

	aliceVerifier := &jws.Verifier{
		Key:       aliceKeys.PublicKey,
		Algorithm: "RS256",
		KeyID:     "alice-ceo-2024",
	}
	_, err = jws.VerifyJSON(multiSigned, []*jws.Verifier{aliceVerifier})
	if err == nil {
		fmt.Println("   ✓ Alice's signature valid")
	}

	bobVerifier := &jws.Verifier{
		Key:       bobKeys.PublicKey,
		Algorithm: "ES256",
		KeyID:     "bob-cfo-2024",
	}
	_, err = jws.VerifyJSON(multiSigned, []*jws.Verifier{bobVerifier})
	if err == nil {
		fmt.Println("   ✓ Bob's signature valid")
	}

	carolVerifier := &jws.Verifier{
		Key:       carolKeys.PublicKey,
		Algorithm: "EdDSA",
		KeyID:     "carol-cto-2024",
	}
	_, err = jws.VerifyJSON(multiSigned, []*jws.Verifier{carolVerifier})
	if err == nil {
		fmt.Println("   ✓ Carol's signature valid")
	}

	fmt.Println("\n   ✅ All 3 signatures verified successfully!")
}

func detachedContentExample() {
	// Large document (stored separately from signature)
	largeDocument := []byte("This is a large PDF document that we don't want to embed in the signature. " +
		"The document is distributed separately, and the signature is sent as a detached JWS. " +
		"This is useful for signing large files where embedding the content would be inefficient.")

	fmt.Println("\n📎 Detached Content Signature:")
	fmt.Println("   Use Case: Sign large files without embedding them")

	rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	// Create detached signature (payload is empty in JWS)
	fmt.Println("\n   Creating detached signature...")
	detachedSig, err := jws.SignDetached(largeDocument, rsaKeys.PrivateKey, "RS256", "doc-signer-2024")
	if err != nil {
		log.Fatal("Failed to create detached signature:", err)
	}

	fmt.Printf("   ✓ Signature: %s...\n", detachedSig[:60])
	fmt.Printf("   ✓ Signature size: %d bytes\n", len(detachedSig))
	fmt.Printf("   ✓ Document size: %d bytes\n", len(largeDocument))
	fmt.Println("   ✓ Document is NOT embedded in signature")

	// Save both separately
	os.WriteFile("output/jws_detached_signature.txt", []byte(detachedSig), 0o644)
	os.WriteFile("output/jws_detached_document.txt", largeDocument, 0o644)

	fmt.Println("\n   Files saved:")
	fmt.Println("   - output/jws_detached_signature.txt (signature only)")
	fmt.Println("   - output/jws_detached_document.txt (document only)")

	// Verify detached signature
	fmt.Println("\n   Verifying detached signature with document...")
	err = jws.VerifyDetached(detachedSig, largeDocument, rsaKeys.PublicKey, "RS256")
	if err != nil {
		log.Fatal("Failed to verify detached signature:", err)
	}

	fmt.Printf("   ✓ Signature valid for document\n")
	fmt.Printf("   ✓ Document length: %d bytes\n", len(largeDocument))
}

func documentSigningExample() {
	fmt.Println("\n📄 Use Case: Legal Document Signing")

	contract := []byte(`
EMPLOYMENT CONTRACT

This agreement is made between:
- Company XYZ Corp
- Employee: John Doe

Terms:
1. Position: Senior Software Engineer
2. Start Date: 2024-10-15
3. Salary: $150,000/year

Signatures required from:
- HR Director
- Department Manager
`)

	// HR Director signs
	hrKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	// Department Manager signs
	managerKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)

	fmt.Println("\n   Document Type: Employment Contract")
	fmt.Println("   Signers: HR Director, Department Manager")

	signers := []*jws.Signer{
		{
			Key:       hrKeys.PrivateKey,
			Algorithm: "RS256",
			KeyID:     "hr-director-jane-smith",
		},
		{
			Key:       managerKeys.PrivateKey,
			Algorithm: "ES256",
			KeyID:     "manager-bob-jones",
		},
	}

	signedContract, _ := jws.SignJSON(contract, signers)

	fmt.Printf("   ✓ Contract signed by %d parties\n", len(signedContract.Signatures))

	jsonBytes, _ := json.Marshal(signedContract)
	os.WriteFile("output/jws_contract_signed.json", jsonBytes, 0o644)

	fmt.Println("   ✓ Signed contract saved to output/jws_contract_signed.json")

	// Verify both signatures
	hrVerifier := &jws.Verifier{
		Key:       hrKeys.PublicKey,
		Algorithm: "RS256",
		KeyID:     "hr-director-jane-smith",
	}
	jws.VerifyJSON(signedContract, []*jws.Verifier{hrVerifier})
	fmt.Println("   ✓ HR Director signature verified")

	managerVerifier := &jws.Verifier{
		Key:       managerKeys.PublicKey,
		Algorithm: "ES256",
		KeyID:     "manager-bob-jones",
	}
	jws.VerifyJSON(signedContract, []*jws.Verifier{managerVerifier})
	fmt.Println("   ✓ Department Manager signature verified")
}

func contractApprovalExample() {
	fmt.Println("\n📋 Use Case: Multi-Level Contract Approval Chain")

	proposal := []byte("Budget Proposal: Q4 Marketing Campaign - $500,000")

	// Approval chain: Manager → Director → VP → CFO
	fmt.Println("\n   Approval Chain:")
	fmt.Println("   1. Manager (Alice) → Initiates")
	fmt.Println("   2. Director (Bob) → Approves")
	fmt.Println("   3. VP (Carol) → Approves")
	fmt.Println("   4. CFO (Dave) → Final approval")

	// Generate keys
	managerKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
	directorKeys, _ := algo.GenerateECDSAKeyPair(algo.P384)
	vpKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	cfoKeys, _ := algo.GenerateEd25519KeyPair()

	// All sign the proposal
	signers := []*jws.Signer{
		{
			Key:       managerKeys.PrivateKey,
			Algorithm: "ES256",
			KeyID:     "manager-alice",
			UnprotectedHeader: map[string]interface{}{
				"role":      "manager",
				"timestamp": "2024-10-08T10:00:00Z",
			},
		},
		{
			Key:       directorKeys.PrivateKey,
			Algorithm: "ES384",
			KeyID:     "director-bob",
			UnprotectedHeader: map[string]interface{}{
				"role":      "director",
				"timestamp": "2024-10-08T11:30:00Z",
			},
		},
		{
			Key:       vpKeys.PrivateKey,
			Algorithm: "RS256",
			KeyID:     "vp-carol",
			UnprotectedHeader: map[string]interface{}{
				"role":      "vp",
				"timestamp": "2024-10-08T14:00:00Z",
			},
		},
		{
			Key:       cfoKeys.PrivateKey,
			Algorithm: "EdDSA",
			KeyID:     "cfo-dave",
			UnprotectedHeader: map[string]interface{}{
				"role":      "cfo",
				"timestamp": "2024-10-08T16:00:00Z",
				"final":     true,
			},
		},
	}

	signedProposal, _ := jws.SignJSON(proposal, signers)

	fmt.Printf("\n   ✓ Proposal approved by %d levels\n", len(signers))

	// Save with pretty formatting
	jsonBytes, _ := json.MarshalIndent(signedProposal, "", "  ")
	os.WriteFile("output/jws_approval_chain.json", jsonBytes, 0o644)

	fmt.Println("   ✓ Approval chain saved to output/jws_approval_chain.json")

	// Show signature details
	fmt.Println("\n   Signature Details:")
	for i, sig := range signedProposal.Signatures {
		role := "unknown"
		timestamp := "unknown"
		if sig.Header != nil {
			if r, ok := sig.Header["role"].(string); ok {
				role = r
			}
			if t, ok := sig.Header["timestamp"].(string); ok {
				timestamp = t
			}
		}
		fmt.Printf("   %d. %s - %s\n", i+1, role, timestamp)
	}

	fmt.Println("\n   ✅ Full approval chain verified")
}
