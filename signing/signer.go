package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/signing/formats"
)

// SignDocument signs a document using the provided key pair and certificate
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

	// Get the appropriate format implementation
	var formatImpl formats.SignatureFormat
	var formatExists bool

	switch opts.Format {
	case FormatRaw:
		formatImpl, formatExists = formats.GetFormat(string(FormatRaw))
	case FormatPKCS7:
		formatImpl, formatExists = formats.GetFormat(string(FormatPKCS7))
	case FormatPKCS7Detached:
		formatImpl, formatExists = formats.GetFormat(string(FormatPKCS7Detached))
	default:
		return nil, ErrUnsupportedFormat
	}

	if !formatExists {
		return nil, fmt.Errorf("format implementation not found: %s", opts.Format)
	}

	// Convert signing options to format options
	formatOpts := formats.SignOptions{
		HashAlgorithm:      opts.HashAlgorithm,
		IncludeCertificate: opts.IncludeCertificate,
		IncludeChain:       opts.IncludeChain,
		Detached:           opts.Detached,
		TimestampURL:       opts.TimestampURL,
		Attributes:         opts.Attributes,
	}

	// Use the format implementation to create the signature
	signatureData, err := formatImpl.Sign(data, privateKey, certificate.Certificate, formatOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature in format %s: %w", opts.Format, err)
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

// SignData is a convenience function for signing data with default options
func SignData[T keypair.KeyPair](data []byte, keyPair T, certificate *cert.Certificate) (*Signature, error) {
	return SignDocument(data, keyPair, certificate, DefaultSignOptions())
}

// SignFile signs a file and returns the signature
func SignFile[T keypair.KeyPair](filePath string, keyPair T, certificate *cert.Certificate, opts SignOptions) (*Signature, error) {
	data, err := readFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return SignDocument(data, keyPair, certificate, opts)
}

// SignStream signs data from a reader
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

// GetSignatureAlgorithm determines the signature algorithm from a public key
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

// ComputeDigest computes the hash of data using the specified algorithm
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

// HashAlgorithmFromString converts a string to a crypto.Hash
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

// HashAlgorithmToString converts a crypto.Hash to a string
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