# GoPKI Encryption Examples

This directory contains comprehensive examples demonstrating the encryption capabilities of the GoPKI library.

## Overview

The encryption example showcases:

1. **RSA-OAEP Encryption** - Direct RSA encryption for small data
2. **ECDSA + ECDH Encryption** - Elliptic curve key agreement with AES-GCM
3. **Ed25519 + X25519 Encryption** - Modern elliptic curve encryption
4. **Envelope Encryption** - Hybrid encryption for large data sets
5. **Certificate-based Encryption** - PKI document encryption workflows
6. **Format Support** - CMS (RFC 5652) format encoding
7. **Multi-Recipient Encryption** - Encrypting for multiple recipients

## Running the Examples

```bash
# From the project root
cd examples/encryption
go run main.go
```

Or using the Taskfile:

```bash
# From the project root
task examples:encryption
```

## Output

The examples will create an `output/` directory containing:

- **Encrypted data files** in various formats
- **Certificates** used for encryption
- **Format demonstrations** showing CMS encoding

## Example Output Structure

```
examples/encryption/output/
├── rsa_encrypted.bin           # RSA-OAEP encrypted data
├── ecdsa_encrypted.bin         # ECDH encrypted data
├── ed25519_encrypted.bin       # X25519 encrypted data
├── envelope_encrypted.raw      # Large data envelope encryption
├── alice_cert.pem              # Certificate for document encryption
├── document_encrypted.bin      # Certificate-based encrypted document
├── format_cms.bin              # CMS format example
├── alice_message.bin           # Multi-recipient: Alice's copy
├── bob_message.bin             # Multi-recipient: Bob's copy
└── charlie_message.bin         # Multi-recipient: Charlie's copy
```

## Key Concepts Demonstrated

### 1. Algorithm Selection

The examples show how GoPKI automatically selects the appropriate encryption algorithm based on the key type:

- **RSA keys** → RSA-OAEP encryption
- **ECDSA keys** → ECDH key agreement + AES-GCM
- **Ed25519 keys** → X25519 key agreement + AES-GCM

### 2. Data Size Handling

- **Small data** (≤190 bytes for RSA-2048) → Direct asymmetric encryption
- **Large data** → Automatic envelope encryption for efficiency

### 3. Format Support

CMS (Cryptographic Message Syntax) format is supported:

- **CMS**: RFC 5652 standard format for enterprise PKI environments
- **Standards compliance**: Compatible with OpenSSL and other PKI tools
- **Advanced features**: Multi-recipient support, algorithm agility, extensible attributes

### 4. Security Features

- **Authenticated encryption** using AES-GCM
- **Forward secrecy** through ephemeral key generation
- **Key agreement protocols** for ECDH and X25519
- **Semantic security** preventing identical plaintext attacks

### 5. Enterprise Integration

- **Certificate-based workflows** for PKI environments
- **Multi-recipient scenarios** for collaborative encryption
- **Standards compliance** for interoperability

## Code Highlights

### Basic Encryption

```go
// Generate key pair
rsaKeys, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)

// Encrypt data
encrypted, err := encryption.EncryptData(data, rsaKeys, encryption.DefaultEncryptOptions())

// Decrypt data
decrypted, err := encryption.DecryptData(encrypted, rsaKeys, encryption.DefaultDecryptOptions())
```

### Certificate-based Encryption

```go
// Create certificate
certificate, err := cert.CreateSelfSignedCertificate(keyPair, certRequest)

// Encrypt for certificate holder
encrypted, err := encryption.EncryptForCertificate(document, certificate, opts)

// Decrypt with private key
decrypted, err := encryption.DecryptData(encrypted, keyPair, decryptOpts)
```

### Format Handling

```go
// Encode to CMS format
encodedData, err := encryption.EncodeData(encrypted)

// Decode from CMS format
decodedData, err := encryption.DecodeData(encodedData)

// Validate CMS format
err := encryption.ValidateEncodedData(encodedData)
```

## Performance Considerations

- **RSA encryption** is limited by key size (~190 bytes for 2048-bit keys)
- **Envelope encryption** is recommended for data >1KB
- **ECDH/X25519** provide excellent performance for any data size
- **CMS format** provides excellent standards compliance with minimal overhead

## Security Best Practices

1. **Use strong key sizes** (RSA ≥2048, ECDSA P-256+)
2. **Validate certificates** before encryption in production
3. **Use envelope encryption** for large data sets
4. **Consider format requirements** for interoperability
5. **Protect private keys** appropriately

## Integration with Other GoPKI Components

The encryption examples demonstrate integration with:

- **keypair package** for key generation
- **cert package** for certificate operations
- **formats package** for output encoding
- **PKI workflows** for enterprise scenarios

This showcases the cohesive design of the GoPKI ecosystem.