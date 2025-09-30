package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"os"

	"github.com/smallstep/pkcs7"

	"github.com/jasoet/gopki/cert"
	internalcrypto "github.com/jasoet/gopki/internal/crypto"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// SignDocument signs a document using the provided key pair and certificate.
// This is the primary function for creating digital signatures with full control
// over signing options and formats.
//
// The function supports all major cryptographic algorithms:
//   - RSA with PKCS#1 v1.5 padding
//   - ECDSA with ASN.1 DER encoding
//   - Ed25519 with native signature format
//
// Type parameter:
//   - T: Key pair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - data: The data to be signed (must not be empty)
//   - keyPair: The cryptographic key pair for signing
//   - certificate: The X.509 certificate associated with the signing key
//   - opts: Signing options (format, hash algorithm, certificate inclusion, etc.)
//
// Returns a Signature containing the signature data, metadata, and certificate information,
// or an error if signing fails.
//
// The function automatically selects the appropriate hash algorithm if not specified
// in the options, based on the key type and size for optimal security.
//
// Supported formats:
//   - FormatPKCS7: PKCS#7/CMS signature container (default)
//   - FormatPKCS7Detached: Detached PKCS#7/CMS signature
//
// Example:
//
//	opts := DefaultSignOptions()
//	opts.Format = FormatPKCS7
//	opts.IncludeChain = true
//
//	signature, err := SignDocument(document, rsaKeyPair, certificate, opts)
//	if err != nil {
//		log.Printf("Signing failed: %v", err)
//		return
//	}
//
//	fmt.Printf("Created %s signature using %s\n", signature.Format, signature.Algorithm)
func SignDocument[T keypair.KeyPair](data []byte, keyPair T, certificate *cert.Certificate, opts SignOptions) (*Signature, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot sign empty data")
	}

	if certificate == nil || certificate.Certificate == nil {
		return nil, ErrMissingCertificate
	}

	// Determine the algorithm and extract private key
	var privateKey crypto.Signer
	var algorithm SignatureAlgorithm

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKey = kp.PrivateKey
		algorithm = AlgorithmRSA
	case *algo.ECDSAKeyPair:
		privateKey = kp.PrivateKey
		algorithm = AlgorithmECDSA
	case *algo.Ed25519KeyPair:
		privateKey = kp.PrivateKey
		algorithm = AlgorithmEd25519
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	// Use default options if hash algorithm not specified
	if opts.HashAlgorithm == 0 {
		opts.HashAlgorithm = getDefaultHashAlgorithm(algorithm, privateKey)
	}

	var signatureData []byte

	// Use PKCS#7 for all algorithms including Ed25519 (now supported via internal implementation)
	if algorithm == AlgorithmEd25519 {
		// Use our custom Ed25519 PKCS#7 implementation (RFC 8419)
		ed25519PrivKey, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid Ed25519 private key type")
		}

		// Use RFC 8419 ASN.1 Ed25519 PKCS#7 format
		pkcs7Data, err := internalcrypto.CreateEd25519PKCS7Signature(data, ed25519PrivKey, certificate.Certificate, opts.Detached)
		if err != nil {
			return nil, fmt.Errorf("failed to create Ed25519 PKCS#7 signature: %w", err)
		}
		signatureData = pkcs7Data
	} else {
		// Use PKCS#7 for RSA and ECDSA
		signedData, err := pkcs7.NewSignedData(data)
		if err != nil {
			return nil, fmt.Errorf("failed to create signed data: %w", err)
		}

		// Set digest algorithm if specified
		if opts.HashAlgorithm != 0 {
			digestOID, err := getDigestAlgorithmOID(opts.HashAlgorithm)
			if err != nil {
				return nil, fmt.Errorf("unsupported hash algorithm: %w", err)
			}
			signedData.SetDigestAlgorithm(digestOID)
		}

		// Add signer
		signerConfig := pkcs7.SignerInfoConfig{}
		err = signedData.AddSigner(certificate.Certificate, privateKey, signerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to add signer: %w", err)
		}

		// Add certificates if requested
		if opts.IncludeCertificate {
			signedData.AddCertificate(certificate.Certificate)
		}

		// Add extra certificates
		for _, extraCert := range opts.ExtraCertificates {
			signedData.AddCertificate(extraCert)
		}

		// Create detached signature if requested
		if opts.Format == FormatPKCS7Detached {
			signedData.Detach()
		}

		// Finalize and get signature data
		signatureData, err = signedData.Finish()
		if err != nil {
			return nil, fmt.Errorf("failed to finalize signature: %w", err)
		}
	}

	// Compute digest for metadata (some formats may need this separately)
	var digest []byte
	if algorithm == AlgorithmEd25519 {
		// For Ed25519, we still compute the digest for metadata purposes
		hasher := opts.HashAlgorithm.New()
		if _, err := hasher.Write(data); err != nil {
			return nil, fmt.Errorf("failed to hash data for metadata: %w", err)
		}
		digest = hasher.Sum(nil)
	} else {
		// For other algorithms, compute the digest normally
		hasher := opts.HashAlgorithm.New()
		if _, err := hasher.Write(data); err != nil {
			return nil, fmt.Errorf("failed to hash data: %w", err)
		}
		digest = hasher.Sum(nil)
	}

	// Create the signature object
	sig := &Signature{
		Format:        opts.Format,
		Algorithm:     algorithm,
		HashAlgorithm: opts.HashAlgorithm,
		Data:          signatureData,
		Digest:        digest,
		Metadata:      opts.Attributes,
	}

	// Include certificate if requested (format may have already included it)
	if opts.IncludeCertificate {
		sig.Certificate = certificate.Certificate
	}

	// Include certificate chain if requested
	if opts.IncludeChain && len(certificate.Certificate.Raw) > 0 {
		// For now, just include the signing certificate
		// In a full implementation, we would build the complete chain
		sig.CertificateChain = []*x509.Certificate{certificate.Certificate}
	}

	return sig, nil
}

// SignData is a convenience function for signing data with default options.
// This function provides a simple interface for common signing scenarios where
// default settings are sufficient.
//
// The function uses DefaultSignOptions() which provides:
//   - PKCS#7/CMS signature format
//   - Auto-selected hash algorithm
//   - Certificate inclusion enabled
//   - Non-detached signature
//
// Type parameter:
//   - T: Key pair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - data: The data to be signed
//   - keyPair: The cryptographic key pair for signing
//   - certificate: The X.509 certificate associated with the signing key
//
// Returns a Signature with default options applied, or an error if signing fails.
//
// For more control over signing parameters, use SignDocument() with custom options.
//
// Example:
//
//	signature, err := SignData(document, rsaKeyPair, certificate)
//	if err != nil {
//		log.Printf("Signing failed: %v", err)
//		return
//	}
//
//	// Verify the signature
//	err = VerifySignature(document, signature, DefaultVerifyOptions())
func SignData[T keypair.KeyPair](data []byte, keyPair T, certificate *cert.Certificate) (*Signature, error) {
	return SignDocument(data, keyPair, certificate, DefaultSignOptions())
}

// SignFile signs a file and returns the signature.
// This convenience function reads a file from disk and signs its contents
// using the specified options.
//
// The function reads the entire file into memory, so it may not be suitable
// for very large files. For streaming large files, use SignStream() instead.
//
// Type parameter:
//   - T: Key pair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - filePath: Path to the file to be signed
//   - keyPair: The cryptographic key pair for signing
//   - certificate: The X.509 certificate associated with the signing key
//   - opts: Signing options (format, hash algorithm, certificate inclusion, etc.)
//
// Returns a Signature for the file contents, or an error if reading or signing fails.
//
// Example:
//
//	opts := DefaultSignOptions()
//	opts.Format = FormatPKCS7Detached
//
//	signature, err := SignFile("/path/to/document.pdf", rsaKeyPair, certificate, opts)
//	if err != nil {
//		log.Printf("File signing failed: %v", err)
//		return
//	}
//
//	// Save signature to a separate file
//	err = os.WriteFile("/path/to/document.pdf.sig", signature.Data, 0644)
func SignFile[T keypair.KeyPair](filePath string, keyPair T, certificate *cert.Certificate, opts SignOptions) (*Signature, error) {
	data, err := readFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return SignDocument(data, keyPair, certificate, opts)
}

// SignStream signs data from a reader, supporting streaming for large data.
// This function is optimized for processing large amounts of data that may not
// fit comfortably in memory.
//
// Algorithm-specific behavior:
//   - RSA/ECDSA: Stream data through hash function, then sign the digest
//   - Ed25519: Must read entire data into memory (Ed25519 requirement)
//
// This function is ideal for signing large files, network streams, or any
// data source where memory usage needs to be controlled.
//
// Type parameter:
//   - T: Key pair type (*algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair)
//
// Parameters:
//   - reader: io.Reader providing the data to be signed
//   - keyPair: The cryptographic key pair for signing
//   - certificate: The X.509 certificate associated with the signing key
//   - opts: Signing options (format, hash algorithm, certificate inclusion, etc.)
//
// Returns a Signature for the streamed data, or an error if reading or signing fails.
//
// Note: For Ed25519 signatures, the entire stream will be read into memory due to
// algorithm requirements. For memory-constrained environments with large data,
// consider using RSA or ECDSA algorithms instead.
//
// Example:
//
//	file, err := os.Open("/path/to/large-file.bin")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer file.Close()
//
//	opts := DefaultSignOptions()
//	opts.HashAlgorithm = crypto.SHA256
//
//	signature, err := SignStream(file, ecdsaKeyPair, certificate, opts)
//	if err != nil {
//		log.Printf("Stream signing failed: %v", err)
//		return
//	}
func SignStream[T keypair.KeyPair](reader io.Reader, keyPair T, certificate *cert.Certificate, opts SignOptions) (*Signature, error) {
	// Determine the algorithm and extract private key
	var privateKey crypto.Signer
	var algorithm SignatureAlgorithm

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKey = kp.PrivateKey
		algorithm = AlgorithmRSA
	case *algo.ECDSAKeyPair:
		privateKey = kp.PrivateKey
		algorithm = AlgorithmECDSA
	case *algo.Ed25519KeyPair:
		privateKey = kp.PrivateKey
		algorithm = AlgorithmEd25519
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	// Use default options if hash algorithm not specified
	if opts.HashAlgorithm == 0 {
		opts.HashAlgorithm = getDefaultHashAlgorithm(algorithm, privateKey)
	}

	var digest []byte
	var signatureData []byte
	var err error

	if algorithm == AlgorithmEd25519 {
		// Ed25519 needs the full message, so we need to read it all into memory
		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read stream data: %w", err)
		}

		// Compute digest for metadata
		hasher := opts.HashAlgorithm.New()
		hasher.Write(data)
		digest = hasher.Sum(nil)

		// Sign the message directly
		signatureData, err = privateKey.Sign(rand.Reader, data, crypto.Hash(0))
	} else {
		// For RSA/ECDSA, stream and hash the data
		hasher := opts.HashAlgorithm.New()
		if _, err := io.Copy(hasher, reader); err != nil {
			return nil, fmt.Errorf("failed to read and hash stream: %w", err)
		}
		digest = hasher.Sum(nil)

		// Sign the digest
		signatureData, err = privateKey.Sign(rand.Reader, digest, opts.HashAlgorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	// Create the signature object
	sig := &Signature{
		Format:        opts.Format,
		Algorithm:     algorithm,
		HashAlgorithm: opts.HashAlgorithm,
		Data:          signatureData,
		Digest:        digest,
		Certificate:   certificate.Certificate,
		Metadata:      opts.Attributes,
	}

	return sig, nil
}

// getDefaultHashAlgorithm returns the default hash algorithm for a given signing algorithm
func getDefaultHashAlgorithm(algo SignatureAlgorithm, signer crypto.Signer) crypto.Hash {
	switch algo {
	case AlgorithmRSA:
		if rsaKey, ok := signer.(*rsa.PrivateKey); ok {
			if rsaKey.N.BitLen() >= 3072 {
				return crypto.SHA384
			}
		}
		return crypto.SHA256
	case AlgorithmECDSA:
		if ecdsaKey, ok := signer.(*ecdsa.PrivateKey); ok {
			switch ecdsaKey.Curve.Params().BitSize {
			case 521:
				return crypto.SHA512
			case 384:
				return crypto.SHA384
			default:
				return crypto.SHA256
			}
		}
		return crypto.SHA256
	case AlgorithmEd25519:
		// Ed25519 always uses SHA-512 internally
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// readFile reads a file and returns its contents
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// Utility functions for working with signatures

// GetSignatureAlgorithm determines the signature algorithm from a public key.
// This function examines the type of the public key and returns the corresponding
// signature algorithm identifier.
//
// Supported key types:
//   - *rsa.PublicKey: Returns AlgorithmRSA
//   - *ecdsa.PublicKey: Returns AlgorithmECDSA
//   - ed25519.PublicKey: Returns AlgorithmEd25519
//
// Parameters:
//   - publicKey: The public key to analyze (crypto.PublicKey interface)
//
// Returns the corresponding SignatureAlgorithm, or an error if the key type
// is not supported.
//
// This function is commonly used when verifying signatures where the algorithm
// needs to be determined from certificate or key material.
//
// Example:
//
//	cert, err := x509.ParseCertificate(certDER)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	algorithm, err := GetSignatureAlgorithm(cert.PublicKey)
//	if err != nil {
//		log.Printf("Unsupported key algorithm: %v", err)
//		return
//	}
//
//	fmt.Printf("Certificate uses %s algorithm\n", algorithm)
func GetSignatureAlgorithm(publicKey crypto.PublicKey) (SignatureAlgorithm, error) {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		return AlgorithmRSA, nil
	case *ecdsa.PublicKey:
		return AlgorithmECDSA, nil
	case ed25519.PublicKey:
		return AlgorithmEd25519, nil
	default:
		return "", ErrUnsupportedAlgorithm
	}
}

// ComputeDigest computes the hash of data using the specified algorithm.
// This utility function provides a convenient way to compute cryptographic
// hashes with proper error handling and availability checking.
//
// Supported hash algorithms include:
//   - crypto.SHA256: 256-bit SHA-2 (most common)
//   - crypto.SHA384: 384-bit SHA-2
//   - crypto.SHA512: 512-bit SHA-2
//   - crypto.SHA224: 224-bit SHA-2
//   - And other algorithms supported by the Go crypto package
//
// Parameters:
//   - data: The data to hash
//   - hashAlgo: The cryptographic hash algorithm to use
//
// Returns the computed hash digest as a byte slice, or an error if the
// hash algorithm is not available or hashing fails.
//
// The function verifies that the requested hash algorithm is available
// before attempting to use it, preventing runtime panics.
//
// Example:
//
//	data := []byte("Hello, world!")
//	digest, err := ComputeDigest(data, crypto.SHA256)
//	if err != nil {
//		log.Printf("Hashing failed: %v", err)
//		return
//	}
//
//	fmt.Printf("SHA-256 digest: %x\n", digest)
func ComputeDigest(data []byte, hashAlgo crypto.Hash) ([]byte, error) {
	if !hashAlgo.Available() {
		return nil, fmt.Errorf("hash algorithm %v is not available", hashAlgo)
	}

	hasher := hashAlgo.New()
	if _, err := hasher.Write(data); err != nil {
		return nil, fmt.Errorf("failed to hash data: %w", err)
	}

	return hasher.Sum(nil), nil
}

// HashAlgorithmFromString converts a string to a crypto.Hash.
// This function provides a convenient way to parse hash algorithm names
// from configuration files, command-line arguments, or API parameters.
//
// Supported algorithm names (case-sensitive):
//   - "SHA256": crypto.SHA256 (default if unknown)
//   - "SHA384": crypto.SHA384
//   - "SHA512": crypto.SHA512
//   - "SHA224": crypto.SHA224
//
// Parameters:
//   - name: The hash algorithm name as a string
//
// Returns the corresponding crypto.Hash constant, or crypto.SHA256
// as a safe default for unrecognized names.
//
// Example:
//
//	algorithm := HashAlgorithmFromString("SHA384")
//	digest, err := ComputeDigest(data, algorithm)
func HashAlgorithmFromString(name string) crypto.Hash {
	switch name {
	case "SHA256":
		return crypto.SHA256
	case "SHA384":
		return crypto.SHA384
	case "SHA512":
		return crypto.SHA512
	case "SHA224":
		return crypto.SHA224
	default:
		return crypto.SHA256
	}
}

// HashAlgorithmToString converts a crypto.Hash to a string representation.
// This function provides a convenient way to display hash algorithm names
// in logs, error messages, or API responses.
//
// Supported hash algorithms:
//   - crypto.SHA256: Returns "SHA256"
//   - crypto.SHA384: Returns "SHA384"
//   - crypto.SHA512: Returns "SHA512"
//   - crypto.SHA224: Returns "SHA224"
//   - Others: Returns "Unknown"
//
// Parameters:
//   - hash: The crypto.Hash constant to convert
//
// Returns the string representation of the hash algorithm, or "Unknown"
// for unrecognized algorithms.
//
// Example:
//
//	fmt.Printf("Using hash algorithm: %s\n", HashAlgorithmToString(crypto.SHA256))
//	// Output: Using hash algorithm: SHA256
func HashAlgorithmToString(hash crypto.Hash) string {
	switch hash {
	case crypto.SHA256:
		return "SHA256"
	case crypto.SHA384:
		return "SHA384"
	case crypto.SHA512:
		return "SHA512"
	case crypto.SHA224:
		return "SHA224"
	default:
		return "Unknown"
	}
}

// getDigestAlgorithmOID returns the ASN.1 OID for the given hash algorithm
// to be used with the Mozilla PKCS#7 library.
func getDigestAlgorithmOID(hash crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch hash {
	case crypto.SHA256:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, nil // sha256
	case crypto.SHA384:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, nil // sha384
	case crypto.SHA512:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, nil // sha512
	case crypto.SHA224:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}, nil // sha224
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %v", hash)
	}
}
