package transit

import (
	"context"
	"fmt"
)

// HashAlgorithm represents supported hash algorithms for signing.
type HashAlgorithm string

const (
	HashSHA2_256 HashAlgorithm = "sha2-256"
	HashSHA2_384 HashAlgorithm = "sha2-384"
	HashSHA2_512 HashAlgorithm = "sha2-512"
	HashSHA3_256 HashAlgorithm = "sha3-256"
	HashSHA3_384 HashAlgorithm = "sha3-384"
	HashSHA3_512 HashAlgorithm = "sha3-512"
	HashNone     HashAlgorithm = "none" // No hashing (data already hashed)
)

// SignatureAlgorithm represents RSA signature algorithms.
type SignatureAlgorithm string

const (
	SignatureAlgPSS      SignatureAlgorithm = "pss"      // RSA-PSS
	SignatureAlgPKCS1v15 SignatureAlgorithm = "pkcs1v15" // RSASSA-PKCS1-v1_5
)

// MarshalingAlgorithm represents ECDSA signature marshaling formats.
type MarshalingAlgorithm string

const (
	MarshalingASN1 MarshalingAlgorithm = "asn1" // ASN.1 DER encoding
	MarshalingJWS  MarshalingAlgorithm = "jws"  // JWS format (concatenated R||S)
)

// SignOptions contains options for signing operations.
type SignOptions struct {
	// KeyVersion specifies which version of the key to use for signing.
	// If not set, uses the latest version.
	KeyVersion int

	// HashAlgorithm specifies the hash algorithm to use.
	// Defaults to sha2-256 if not specified.
	HashAlgorithm HashAlgorithm

	// Context is required for derived keys and provides key derivation context.
	// Must be base64-encoded.
	Context string

	// Prehashed indicates whether the input is already hashed.
	// If true, HashAlgorithm should typically be "none".
	Prehashed bool

	// SignatureAlgorithm specifies the signature algorithm for RSA keys.
	// Valid values: "pss" (default), "pkcs1v15".
	SignatureAlgorithm SignatureAlgorithm

	// MarshalingAlgorithm specifies how ECDSA signatures are marshaled.
	// Valid values: "asn1" (default), "jws".
	MarshalingAlgorithm MarshalingAlgorithm

	// SaltLength specifies the salt length for RSA-PSS signatures.
	// Valid values: "auto" (default), "hash", or a specific number.
	SaltLength string
}

// VerifyOptions contains options for signature verification.
type VerifyOptions struct {
	// HashAlgorithm specifies the hash algorithm used during signing.
	HashAlgorithm HashAlgorithm

	// Context is required for derived keys.
	// Must be base64-encoded.
	Context string

	// Prehashed indicates whether the input was prehashed.
	Prehashed bool

	// SignatureAlgorithm specifies the signature algorithm for RSA keys.
	SignatureAlgorithm SignatureAlgorithm

	// MarshalingAlgorithm specifies ECDSA signature marshaling format.
	MarshalingAlgorithm MarshalingAlgorithm

	// SaltLength specifies the salt length for RSA-PSS signatures.
	SaltLength string
}

// HMACOptions contains options for HMAC operations.
type HMACOptions struct {
	// KeyVersion specifies which version of the key to use.
	KeyVersion int

	// Algorithm specifies the hash algorithm for HMAC.
	// Defaults to sha2-256 if not specified.
	Algorithm HashAlgorithm
}

// SignatureResult contains the result of a signing operation.
type SignatureResult struct {
	// Signature is the generated signature (format depends on key type).
	Signature string

	// KeyVersion is the version of the key used for signing.
	KeyVersion int

	// PublicKey is the public key in PEM format (if requested).
	PublicKey string
}

// VerificationResult contains the result of a signature verification.
type VerificationResult struct {
	// Valid indicates whether the signature is valid.
	Valid bool
}

// HMACResult contains the result of an HMAC operation.
type HMACResult struct {
	// HMAC is the generated HMAC value.
	HMAC string

	// KeyVersion is the version of the key used.
	KeyVersion int
}

// BatchSignItem represents a single item in a batch signing operation.
type BatchSignItem struct {
	// Input is the data to sign (base64-encoded).
	Input string

	// Context for derived keys (base64-encoded).
	Context string

	// KeyVersion specifies which version to use (optional).
	KeyVersion int

	// HashAlgorithm for this specific item (optional).
	HashAlgorithm string

	// Prehashed indicates if input is already hashed.
	Prehashed bool

	// SignatureAlgorithm for RSA keys (optional).
	SignatureAlgorithm string

	// MarshalingAlgorithm for ECDSA keys (optional).
	MarshalingAlgorithm string

	// SaltLength for RSA-PSS (optional).
	SaltLength string
}

// BatchVerifyItem represents a single item in a batch verification operation.
type BatchVerifyItem struct {
	// Input is the data that was signed (base64-encoded).
	Input string

	// Signature is the signature to verify.
	Signature string

	// HMAC is the HMAC to verify (alternative to Signature).
	HMAC string

	// Context for derived keys (base64-encoded).
	Context string

	// HashAlgorithm used during signing (optional).
	HashAlgorithm string

	// Prehashed indicates if input was prehashed.
	Prehashed bool

	// SignatureAlgorithm for RSA keys (optional).
	SignatureAlgorithm string

	// MarshalingAlgorithm for ECDSA keys (optional).
	MarshalingAlgorithm string

	// SaltLength for RSA-PSS (optional).
	SaltLength string
}

// BatchSignResult contains results from a batch signing operation.
type BatchSignResult struct {
	// Results contains the signature results for each item.
	Results []SignatureResult

	// Errors contains any errors for each item (nil if successful).
	Errors []error
}

// BatchVerifyResult contains results from a batch verification operation.
type BatchVerifyResult struct {
	// Results contains the verification results for each item.
	Results []VerificationResult

	// Errors contains any errors for each item (nil if successful).
	Errors []error
}

// Sign signs the given input data using the specified key.
// Input should be base64-encoded.
func (c *Client) Sign(ctx context.Context, keyName, input string, opts *SignOptions) (*SignatureResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("key name cannot be empty")
	}
	if input == "" {
		return nil, fmt.Errorf("input cannot be empty")
	}

	path := fmt.Sprintf("sign/%s", keyName)

	payload := map[string]interface{}{
		"input": input,
	}

	if opts != nil {
		if opts.KeyVersion > 0 {
			payload["key_version"] = opts.KeyVersion
		}
		if opts.HashAlgorithm != "" {
			payload["hash_algorithm"] = string(opts.HashAlgorithm)
		}
		if opts.Context != "" {
			payload["context"] = opts.Context
		}
		if opts.Prehashed {
			payload["prehashed"] = true
		}
		if opts.SignatureAlgorithm != "" {
			payload["signature_algorithm"] = string(opts.SignatureAlgorithm)
		}
		if opts.MarshalingAlgorithm != "" {
			payload["marshaling_algorithm"] = string(opts.MarshalingAlgorithm)
		}
		if opts.SaltLength != "" {
			payload["salt_length"] = opts.SaltLength
		}
	}

	secret, err := c.write(ctx, path, payload)
	if err != nil {
		return nil, fmt.Errorf("transit Sign: %w", err)
	}

	result := &SignatureResult{
		Signature: secret.Data["signature"].(string),
	}

	// Extract key version if present
	if kv, ok := secret.Data["key_version"]; ok {
		result.KeyVersion = getInt(secret.Data, "key_version")
		_ = kv // Mark as used
	}

	// Extract public key if present
	if pk, ok := secret.Data["public_key"].(string); ok {
		result.PublicKey = pk
	}

	return result, nil
}

// Verify verifies a signature for the given input data.
// Input should be base64-encoded.
func (c *Client) Verify(ctx context.Context, keyName, input, signature string, opts *VerifyOptions) (*VerificationResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("key name cannot be empty")
	}
	if input == "" {
		return nil, fmt.Errorf("input cannot be empty")
	}
	if signature == "" {
		return nil, fmt.Errorf("signature cannot be empty")
	}

	path := fmt.Sprintf("verify/%s", keyName)

	payload := map[string]interface{}{
		"input":     input,
		"signature": signature,
	}

	if opts != nil {
		if opts.HashAlgorithm != "" {
			payload["hash_algorithm"] = string(opts.HashAlgorithm)
		}
		if opts.Context != "" {
			payload["context"] = opts.Context
		}
		if opts.Prehashed {
			payload["prehashed"] = true
		}
		if opts.SignatureAlgorithm != "" {
			payload["signature_algorithm"] = string(opts.SignatureAlgorithm)
		}
		if opts.MarshalingAlgorithm != "" {
			payload["marshaling_algorithm"] = string(opts.MarshalingAlgorithm)
		}
		if opts.SaltLength != "" {
			payload["salt_length"] = opts.SaltLength
		}
	}

	secret, err := c.write(ctx, path, payload)
	if err != nil {
		return nil, fmt.Errorf("transit Verify: %w", err)
	}

	result := &VerificationResult{
		Valid: secret.Data["valid"].(bool),
	}

	return result, nil
}

// HMAC generates an HMAC for the given input using the specified key.
// The key must be of a type that supports HMAC operations.
// Input should be base64-encoded.
func (c *Client) HMAC(ctx context.Context, keyName, input string, opts *HMACOptions) (*HMACResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("key name cannot be empty")
	}
	if input == "" {
		return nil, fmt.Errorf("input cannot be empty")
	}

	path := fmt.Sprintf("hmac/%s", keyName)

	payload := map[string]interface{}{
		"input": input,
	}

	if opts != nil {
		if opts.KeyVersion > 0 {
			payload["key_version"] = opts.KeyVersion
		}
		if opts.Algorithm != "" {
			payload["algorithm"] = string(opts.Algorithm)
		}
	}

	secret, err := c.write(ctx, path, payload)
	if err != nil {
		return nil, fmt.Errorf("transit HMAC: %w", err)
	}

	result := &HMACResult{
		HMAC: secret.Data["hmac"].(string),
	}

	// Extract key version if present
	if kv, ok := secret.Data["key_version"]; ok {
		result.KeyVersion = getInt(secret.Data, "key_version")
		_ = kv // Mark as used
	}

	return result, nil
}

// VerifyHMAC verifies an HMAC for the given input.
// Input should be base64-encoded.
func (c *Client) VerifyHMAC(ctx context.Context, keyName, input, hmac string, opts *HMACOptions) (*VerificationResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("key name cannot be empty")
	}
	if input == "" {
		return nil, fmt.Errorf("input cannot be empty")
	}
	if hmac == "" {
		return nil, fmt.Errorf("hmac cannot be empty")
	}

	path := fmt.Sprintf("verify/%s", keyName)

	payload := map[string]interface{}{
		"input": input,
		"hmac":  hmac,
	}

	if opts != nil {
		if opts.Algorithm != "" {
			payload["algorithm"] = string(opts.Algorithm)
		}
	}

	secret, err := c.write(ctx, path, payload)
	if err != nil {
		return nil, fmt.Errorf("transit VerifyHMAC: %w", err)
	}

	result := &VerificationResult{
		Valid: secret.Data["valid"].(bool),
	}

	return result, nil
}

// SignBatch signs multiple items in a single request with automatic chunking.
func (c *Client) SignBatch(ctx context.Context, keyName string, items []BatchSignItem) (*BatchSignResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("key name cannot be empty")
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("batch items cannot be empty")
	}

	maxBatch := c.config.MaxBatchSize
	if maxBatch <= 0 {
		maxBatch = DefaultMaxBatchSize
	}
	if maxBatch > AbsoluteMaxBatchSize {
		maxBatch = AbsoluteMaxBatchSize
	}

	result := &BatchSignResult{
		Results: make([]SignatureResult, len(items)),
		Errors:  make([]error, len(items)),
	}

	// Process in chunks
	for i := 0; i < len(items); i += maxBatch {
		end := i + maxBatch
		if end > len(items) {
			end = len(items)
		}
		chunk := items[i:end]

		if err := c.signBatchChunk(ctx, keyName, chunk, result, i); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// signBatchChunk processes a single chunk of batch signing.
func (c *Client) signBatchChunk(ctx context.Context, keyName string, chunk []BatchSignItem, result *BatchSignResult, offset int) error {
	path := fmt.Sprintf("sign/%s", keyName)

	// Convert chunk to API format
	batchInput := make([]map[string]interface{}, len(chunk))
	for i, item := range chunk {
		batchItem := map[string]interface{}{
			"input": item.Input,
		}
		if item.Context != "" {
			batchItem["context"] = item.Context
		}
		if item.KeyVersion > 0 {
			batchItem["key_version"] = item.KeyVersion
		}
		if item.HashAlgorithm != "" {
			batchItem["hash_algorithm"] = item.HashAlgorithm
		}
		if item.Prehashed {
			batchItem["prehashed"] = true
		}
		if item.SignatureAlgorithm != "" {
			batchItem["signature_algorithm"] = item.SignatureAlgorithm
		}
		if item.MarshalingAlgorithm != "" {
			batchItem["marshaling_algorithm"] = item.MarshalingAlgorithm
		}
		if item.SaltLength != "" {
			batchItem["salt_length"] = item.SaltLength
		}
		batchInput[i] = batchItem
	}

	payload := map[string]interface{}{
		"batch_input": batchInput,
	}

	secret, err := c.write(ctx, path, payload)
	if err != nil {
		return fmt.Errorf("transit SignBatch: %w", err)
	}

	// Parse batch results
	batchResults, ok := secret.Data["batch_results"].([]interface{})
	if !ok {
		return fmt.Errorf("unexpected batch_results format")
	}

	for i, item := range batchResults {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			result.Errors[offset+i] = fmt.Errorf("unexpected item format")
			continue
		}

		if errMsg, hasErr := itemMap["error"].(string); hasErr && errMsg != "" {
			result.Errors[offset+i] = fmt.Errorf("%s", errMsg)
			continue
		}

		if sig, ok := itemMap["signature"].(string); ok {
			result.Results[offset+i].Signature = sig
		}
		if kv, ok := itemMap["key_version"]; ok {
			result.Results[offset+i].KeyVersion = getIntFromInterface(kv)
		}
		if pk, ok := itemMap["public_key"].(string); ok {
			result.Results[offset+i].PublicKey = pk
		}
	}

	return nil
}

// VerifyBatch verifies multiple signatures in a single request with automatic chunking.
func (c *Client) VerifyBatch(ctx context.Context, keyName string, items []BatchVerifyItem) (*BatchVerifyResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("key name cannot be empty")
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("batch items cannot be empty")
	}

	maxBatch := c.config.MaxBatchSize
	if maxBatch <= 0 {
		maxBatch = DefaultMaxBatchSize
	}
	if maxBatch > AbsoluteMaxBatchSize {
		maxBatch = AbsoluteMaxBatchSize
	}

	result := &BatchVerifyResult{
		Results: make([]VerificationResult, len(items)),
		Errors:  make([]error, len(items)),
	}

	// Process in chunks
	for i := 0; i < len(items); i += maxBatch {
		end := i + maxBatch
		if end > len(items) {
			end = len(items)
		}
		chunk := items[i:end]

		if err := c.verifyBatchChunk(ctx, keyName, chunk, result, i); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// verifyBatchChunk processes a single chunk of batch verification.
func (c *Client) verifyBatchChunk(ctx context.Context, keyName string, chunk []BatchVerifyItem, result *BatchVerifyResult, offset int) error {
	path := fmt.Sprintf("verify/%s", keyName)

	// Convert chunk to API format
	batchInput := make([]map[string]interface{}, len(chunk))
	for i, item := range chunk {
		batchItem := map[string]interface{}{
			"input": item.Input,
		}
		if item.Signature != "" {
			batchItem["signature"] = item.Signature
		}
		if item.HMAC != "" {
			batchItem["hmac"] = item.HMAC
		}
		if item.Context != "" {
			batchItem["context"] = item.Context
		}
		if item.HashAlgorithm != "" {
			batchItem["hash_algorithm"] = item.HashAlgorithm
		}
		if item.Prehashed {
			batchItem["prehashed"] = true
		}
		if item.SignatureAlgorithm != "" {
			batchItem["signature_algorithm"] = item.SignatureAlgorithm
		}
		if item.MarshalingAlgorithm != "" {
			batchItem["marshaling_algorithm"] = item.MarshalingAlgorithm
		}
		if item.SaltLength != "" {
			batchItem["salt_length"] = item.SaltLength
		}
		batchInput[i] = batchItem
	}

	payload := map[string]interface{}{
		"batch_input": batchInput,
	}

	secret, err := c.write(ctx, path, payload)
	if err != nil {
		return fmt.Errorf("transit VerifyBatch: %w", err)
	}

	// Parse batch results
	batchResults, ok := secret.Data["batch_results"].([]interface{})
	if !ok {
		return fmt.Errorf("unexpected batch_results format")
	}

	for i, item := range batchResults {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			result.Errors[offset+i] = fmt.Errorf("unexpected item format")
			continue
		}

		if errMsg, hasErr := itemMap["error"].(string); hasErr && errMsg != "" {
			result.Errors[offset+i] = fmt.Errorf("%s", errMsg)
			continue
		}

		if valid, ok := itemMap["valid"].(bool); ok {
			result.Results[offset+i].Valid = valid
		}
	}

	return nil
}

// getIntFromInterface safely extracts an integer from interface{}.
func getIntFromInterface(val interface{}) int {
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}
