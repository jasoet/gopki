package transit

import (
	"context"
	"fmt"
)

// EncryptOptions configures encryption behavior.
type EncryptOptions struct {
	// Context is optional base64-encoded data for key derivation (if key is derived).
	// Required if the key was created with derived=true.
	Context string

	// KeyVersion specifies which key version to use for encryption.
	// If 0, uses the latest version.
	KeyVersion int

	// Nonce is optional base64-encoded nonce for convergent encryption.
	// Required if key uses convergent_encryption.
	Nonce string

	// Type specifies the data type for HMAC operations (e.g., "hmac-sha256").
	// Only used with HMAC keys.
	Type string

	// Associated data for AEAD ciphers (additional authenticated data).
	// Not encrypted but authenticated.
	AssociatedData string
}

// DecryptOptions configures decryption behavior.
type DecryptOptions struct {
	// Context is optional base64-encoded data for key derivation.
	// Must match the context used during encryption.
	Context string

	// Nonce is optional base64-encoded nonce.
	// Must match the nonce used during encryption if convergent encryption was used.
	Nonce string

	// Associated data that was provided during encryption.
	AssociatedData string
}

// EncryptionResult contains the encrypted ciphertext.
type EncryptionResult struct {
	// Ciphertext is the encrypted data in Transit format (vault:v1:base64...).
	Ciphertext string

	// KeyVersion is the key version used for encryption.
	KeyVersion int
}

// DecryptionResult contains the decrypted plaintext.
type DecryptionResult struct {
	// Plaintext is the decrypted data (base64-encoded).
	Plaintext string
}

// BatchEncryptItem represents a single item to encrypt in a batch operation.
type BatchEncryptItem struct {
	// Plaintext is the base64-encoded data to encrypt.
	Plaintext string

	// Context is optional base64-encoded context for this item.
	Context string

	// KeyVersion specifies which key version to use (0 for latest).
	KeyVersion int

	// Nonce for convergent encryption (optional).
	Nonce string

	// AssociatedData for AEAD (optional).
	AssociatedData string
}

// BatchDecryptItem represents a single item to decrypt in a batch operation.
type BatchDecryptItem struct {
	// Ciphertext is the encrypted data to decrypt.
	Ciphertext string

	// Context is optional base64-encoded context.
	Context string

	// Nonce for convergent encryption (optional).
	Nonce string

	// AssociatedData for AEAD (optional).
	AssociatedData string
}

// BatchEncryptResult contains results from batch encryption.
type BatchEncryptResult struct {
	// Results contains the encrypted ciphertexts.
	// Index corresponds to input batch order.
	Results []EncryptionResult

	// Errors contains any errors that occurred during batch processing.
	// nil if no errors occurred for that item.
	Errors []error
}

// BatchDecryptResult contains results from batch decryption.
type BatchDecryptResult struct {
	// Results contains the decrypted plaintexts.
	// Index corresponds to input batch order.
	Results []DecryptionResult

	// Errors contains any errors that occurred during batch processing.
	// nil if no errors occurred for that item.
	Errors []error
}

// Encrypt encrypts plaintext data using the specified key.
//
// The plaintext should be base64-encoded before calling this function.
// Returns the ciphertext in Transit format (e.g., "vault:v1:base64...").
//
// Example:
//
//	plaintext := base64.StdEncoding.EncodeToString([]byte("secret data"))
//	result, err := client.Encrypt(ctx, "my-key", plaintext, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println("Ciphertext:", result.Ciphertext)
func (c *Client) Encrypt(ctx context.Context, keyName, plaintext string, opts *EncryptOptions) (*EncryptionResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	if plaintext == "" {
		return nil, fmt.Errorf("%w: plaintext cannot be empty", ErrInvalidConfig)
	}

	data := map[string]interface{}{
		"plaintext": plaintext,
	}

	if opts != nil {
		if opts.Context != "" {
			data["context"] = opts.Context
		}
		if opts.KeyVersion > 0 {
			data["key_version"] = opts.KeyVersion
		}
		if opts.Nonce != "" {
			data["nonce"] = opts.Nonce
		}
		if opts.Type != "" {
			data["type"] = opts.Type
		}
		if opts.AssociatedData != "" {
			data["associated_data"] = opts.AssociatedData
		}
	}

	path := fmt.Sprintf("encrypt/%s", keyName)
	secret, err := c.write(ctx, path, data)
	if err != nil {
		return nil, WrapError("Encrypt", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, WrapError("Encrypt", fmt.Errorf("no encryption data returned"))
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return nil, WrapError("Encrypt", fmt.Errorf("invalid ciphertext format"))
	}

	result := &EncryptionResult{
		Ciphertext: ciphertext,
	}

	// Extract key version if present
	if keyVersion := getInt(secret.Data, "key_version"); keyVersion > 0 {
		result.KeyVersion = keyVersion
	}

	return result, nil
}

// Decrypt decrypts ciphertext data using the specified key.
//
// The ciphertext must be in Transit format (e.g., "vault:v1:base64...").
// Returns the plaintext as base64-encoded data.
//
// Example:
//
//	result, err := client.Decrypt(ctx, "my-key", ciphertext, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	plaintext, _ := base64.StdEncoding.DecodeString(result.Plaintext)
//	fmt.Println("Decrypted:", string(plaintext))
func (c *Client) Decrypt(ctx context.Context, keyName, ciphertext string, opts *DecryptOptions) (*DecryptionResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	if ciphertext == "" {
		return nil, fmt.Errorf("%w: ciphertext cannot be empty", ErrInvalidConfig)
	}

	data := map[string]interface{}{
		"ciphertext": ciphertext,
	}

	if opts != nil {
		if opts.Context != "" {
			data["context"] = opts.Context
		}
		if opts.Nonce != "" {
			data["nonce"] = opts.Nonce
		}
		if opts.AssociatedData != "" {
			data["associated_data"] = opts.AssociatedData
		}
	}

	path := fmt.Sprintf("decrypt/%s", keyName)
	secret, err := c.write(ctx, path, data)
	if err != nil {
		return nil, WrapError("Decrypt", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, WrapError("Decrypt", fmt.Errorf("no decryption data returned"))
	}

	plaintext, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, WrapError("Decrypt", fmt.Errorf("invalid plaintext format"))
	}

	return &DecryptionResult{
		Plaintext: plaintext,
	}, nil
}

// EncryptBatch encrypts multiple plaintexts in a single request.
// Automatically chunks large batches to respect OpenBao's batch size limits.
//
// Example:
//
//	items := []BatchEncryptItem{
//	    {Plaintext: base64.StdEncoding.EncodeToString([]byte("data1"))},
//	    {Plaintext: base64.StdEncoding.EncodeToString([]byte("data2"))},
//	}
//	result, err := client.EncryptBatch(ctx, "my-key", items)
func (c *Client) EncryptBatch(ctx context.Context, keyName string, items []BatchEncryptItem) (*BatchEncryptResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("%w: batch cannot be empty", ErrEmptyBatch)
	}

	maxBatch := c.config.MaxBatchSize
	if maxBatch <= 0 {
		maxBatch = DefaultMaxBatchSize
	}

	result := &BatchEncryptResult{
		Results: make([]EncryptionResult, len(items)),
		Errors:  make([]error, len(items)),
	}

	// Process in chunks
	for i := 0; i < len(items); i += maxBatch {
		end := i + maxBatch
		if end > len(items) {
			end = len(items)
		}

		chunk := items[i:end]
		if err := c.encryptBatchChunk(ctx, keyName, chunk, result, i); err != nil {
			return result, err
		}
	}

	return result, nil
}

// encryptBatchChunk processes a single chunk of batch encryption.
func (c *Client) encryptBatchChunk(ctx context.Context, keyName string, chunk []BatchEncryptItem, result *BatchEncryptResult, offset int) error {
	batchInput := make([]map[string]interface{}, len(chunk))
	for i, item := range chunk {
		entry := map[string]interface{}{
			"plaintext": item.Plaintext,
		}
		if item.Context != "" {
			entry["context"] = item.Context
		}
		if item.KeyVersion > 0 {
			entry["key_version"] = item.KeyVersion
		}
		if item.Nonce != "" {
			entry["nonce"] = item.Nonce
		}
		if item.AssociatedData != "" {
			entry["associated_data"] = item.AssociatedData
		}
		batchInput[i] = entry
	}

	data := map[string]interface{}{
		"batch_input": batchInput,
	}

	path := fmt.Sprintf("encrypt/%s", keyName)
	secret, err := c.write(ctx, path, data)
	if err != nil {
		// If entire batch fails, mark all items as failed
		for i := range chunk {
			result.Errors[offset+i] = WrapError("EncryptBatch", err)
		}
		return WrapError("EncryptBatch", err)
	}

	if secret == nil || secret.Data == nil {
		err := fmt.Errorf("no batch encryption data returned")
		for i := range chunk {
			result.Errors[offset+i] = WrapError("EncryptBatch", err)
		}
		return WrapError("EncryptBatch", err)
	}

	batchResults, ok := secret.Data["batch_results"].([]interface{})
	if !ok {
		err := fmt.Errorf("invalid batch_results format")
		for i := range chunk {
			result.Errors[offset+i] = WrapError("EncryptBatch", err)
		}
		return WrapError("EncryptBatch", err)
	}

	// Parse results
	for i, resultData := range batchResults {
		idx := offset + i
		resultMap, ok := resultData.(map[string]interface{})
		if !ok {
			result.Errors[idx] = WrapError("EncryptBatch", fmt.Errorf("invalid result format at index %d", i))
			continue
		}

		// Check for error in this item
		if errMsg, ok := resultMap["error"].(string); ok && errMsg != "" {
			result.Errors[idx] = WrapError("EncryptBatch", fmt.Errorf("item %d: %s", i, errMsg))
			continue
		}

		ciphertext, ok := resultMap["ciphertext"].(string)
		if !ok {
			result.Errors[idx] = WrapError("EncryptBatch", fmt.Errorf("missing ciphertext at index %d", i))
			continue
		}

		result.Results[idx] = EncryptionResult{
			Ciphertext: ciphertext,
			KeyVersion: getInt(resultMap, "key_version"),
		}
	}

	return nil
}

// DecryptBatch decrypts multiple ciphertexts in a single request.
// Automatically chunks large batches to respect OpenBao's batch size limits.
//
// Example:
//
//	items := []BatchDecryptItem{
//	    {Ciphertext: "vault:v1:abc..."},
//	    {Ciphertext: "vault:v1:def..."},
//	}
//	result, err := client.DecryptBatch(ctx, "my-key", items)
func (c *Client) DecryptBatch(ctx context.Context, keyName string, items []BatchDecryptItem) (*BatchDecryptResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("%w: batch cannot be empty", ErrEmptyBatch)
	}

	maxBatch := c.config.MaxBatchSize
	if maxBatch <= 0 {
		maxBatch = DefaultMaxBatchSize
	}

	result := &BatchDecryptResult{
		Results: make([]DecryptionResult, len(items)),
		Errors:  make([]error, len(items)),
	}

	// Process in chunks
	for i := 0; i < len(items); i += maxBatch {
		end := i + maxBatch
		if end > len(items) {
			end = len(items)
		}

		chunk := items[i:end]
		if err := c.decryptBatchChunk(ctx, keyName, chunk, result, i); err != nil {
			return result, err
		}
	}

	return result, nil
}

// decryptBatchChunk processes a single chunk of batch decryption.
func (c *Client) decryptBatchChunk(ctx context.Context, keyName string, chunk []BatchDecryptItem, result *BatchDecryptResult, offset int) error {
	batchInput := make([]map[string]interface{}, len(chunk))
	for i, item := range chunk {
		entry := map[string]interface{}{
			"ciphertext": item.Ciphertext,
		}
		if item.Context != "" {
			entry["context"] = item.Context
		}
		if item.Nonce != "" {
			entry["nonce"] = item.Nonce
		}
		if item.AssociatedData != "" {
			entry["associated_data"] = item.AssociatedData
		}
		batchInput[i] = entry
	}

	data := map[string]interface{}{
		"batch_input": batchInput,
	}

	path := fmt.Sprintf("decrypt/%s", keyName)
	secret, err := c.write(ctx, path, data)
	if err != nil {
		// If entire batch fails, mark all items as failed
		for i := range chunk {
			result.Errors[offset+i] = WrapError("DecryptBatch", err)
		}
		return WrapError("DecryptBatch", err)
	}

	if secret == nil || secret.Data == nil {
		err := fmt.Errorf("no batch decryption data returned")
		for i := range chunk {
			result.Errors[offset+i] = WrapError("DecryptBatch", err)
		}
		return WrapError("DecryptBatch", err)
	}

	batchResults, ok := secret.Data["batch_results"].([]interface{})
	if !ok {
		err := fmt.Errorf("invalid batch_results format")
		for i := range chunk {
			result.Errors[offset+i] = WrapError("DecryptBatch", err)
		}
		return WrapError("DecryptBatch", err)
	}

	// Parse results
	for i, resultData := range batchResults {
		idx := offset + i
		resultMap, ok := resultData.(map[string]interface{})
		if !ok {
			result.Errors[idx] = WrapError("DecryptBatch", fmt.Errorf("invalid result format at index %d", i))
			continue
		}

		// Check for error in this item
		if errMsg, ok := resultMap["error"].(string); ok && errMsg != "" {
			result.Errors[idx] = WrapError("DecryptBatch", fmt.Errorf("item %d: %s", i, errMsg))
			continue
		}

		plaintext, ok := resultMap["plaintext"].(string)
		if !ok {
			result.Errors[idx] = WrapError("DecryptBatch", fmt.Errorf("missing plaintext at index %d", i))
			continue
		}

		result.Results[idx] = DecryptionResult{
			Plaintext: plaintext,
		}
	}

	return nil
}

// ReEncrypt re-encrypts ciphertext with a new key version.
// This is useful for key rotation without exposing the plaintext.
//
// Example:
//
//	newCiphertext, err := client.ReEncrypt(ctx, "my-key", oldCiphertext, nil)
func (c *Client) ReEncrypt(ctx context.Context, keyName, ciphertext string, opts *EncryptOptions) (*EncryptionResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	if ciphertext == "" {
		return nil, fmt.Errorf("%w: ciphertext cannot be empty", ErrInvalidConfig)
	}

	data := map[string]interface{}{
		"ciphertext": ciphertext,
	}

	if opts != nil {
		if opts.Context != "" {
			data["context"] = opts.Context
		}
		if opts.KeyVersion > 0 {
			data["key_version"] = opts.KeyVersion
		}
		if opts.Nonce != "" {
			data["nonce"] = opts.Nonce
		}
		if opts.AssociatedData != "" {
			data["associated_data"] = opts.AssociatedData
		}
	}

	path := fmt.Sprintf("rewrap/%s", keyName)
	secret, err := c.write(ctx, path, data)
	if err != nil {
		return nil, WrapError("ReEncrypt", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, WrapError("ReEncrypt", fmt.Errorf("no re-encryption data returned"))
	}

	newCiphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return nil, WrapError("ReEncrypt", fmt.Errorf("invalid ciphertext format"))
	}

	result := &EncryptionResult{
		Ciphertext: newCiphertext,
	}

	if keyVersion := getInt(secret.Data, "key_version"); keyVersion > 0 {
		result.KeyVersion = keyVersion
	}

	return result, nil
}

// DataKeyOptions configures data key generation.
type DataKeyOptions struct {
	// Context for key derivation (optional).
	Context string

	// KeyVersion specifies which key version to use (0 for latest).
	KeyVersion int

	// Nonce for convergent encryption (optional).
	Nonce string

	// Bits specifies the size of the data key (e.g., 256 for AES-256).
	// Default is 256.
	Bits int
}

// DataKeyResult contains a generated data key.
type DataKeyResult struct {
	// Plaintext is the base64-encoded data key (only in plaintext response).
	Plaintext string

	// Ciphertext is the encrypted data key (Transit format).
	Ciphertext string

	// KeyVersion is the Transit key version used to encrypt the data key.
	KeyVersion int
}

// GenerateDataKey generates a new data key for envelope encryption.
// Returns both the plaintext key (for immediate use) and encrypted key (for storage).
//
// Example (envelope encryption pattern):
//
//	// Generate data key
//	dataKey, err := client.GenerateDataKey(ctx, "my-key", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use plaintext key to encrypt data locally
//	plainKey, _ := base64.StdEncoding.DecodeString(dataKey.Plaintext)
//	// ... encrypt data with plainKey using AES-GCM ...
//
//	// Store encrypted data key with encrypted data
//	// Later, decrypt data key using Transit, then decrypt data
func (c *Client) GenerateDataKey(ctx context.Context, keyName string, opts *DataKeyOptions) (*DataKeyResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	data := map[string]interface{}{}

	if opts != nil {
		if opts.Context != "" {
			data["context"] = opts.Context
		}
		if opts.KeyVersion > 0 {
			data["key_version"] = opts.KeyVersion
		}
		if opts.Nonce != "" {
			data["nonce"] = opts.Nonce
		}
		if opts.Bits > 0 {
			data["bits"] = opts.Bits
		}
	}

	path := fmt.Sprintf("datakey/plaintext/%s", keyName)
	secret, err := c.write(ctx, path, data)
	if err != nil {
		return nil, WrapError("GenerateDataKey", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, WrapError("GenerateDataKey", fmt.Errorf("no data key returned"))
	}

	plaintext, _ := secret.Data["plaintext"].(string)
	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return nil, WrapError("GenerateDataKey", fmt.Errorf("invalid ciphertext format"))
	}

	return &DataKeyResult{
		Plaintext:  plaintext,
		Ciphertext: ciphertext,
		KeyVersion: getInt(secret.Data, "key_version"),
	}, nil
}

// GenerateWrappedDataKey generates a data key but only returns the encrypted version.
// Use this when you don't need the plaintext key immediately.
func (c *Client) GenerateWrappedDataKey(ctx context.Context, keyName string, opts *DataKeyOptions) (*DataKeyResult, error) {
	if keyName == "" {
		return nil, fmt.Errorf("%w: key name cannot be empty", ErrInvalidConfig)
	}

	data := map[string]interface{}{}

	if opts != nil {
		if opts.Context != "" {
			data["context"] = opts.Context
		}
		if opts.KeyVersion > 0 {
			data["key_version"] = opts.KeyVersion
		}
		if opts.Nonce != "" {
			data["nonce"] = opts.Nonce
		}
		if opts.Bits > 0 {
			data["bits"] = opts.Bits
		}
	}

	path := fmt.Sprintf("datakey/wrapped/%s", keyName)
	secret, err := c.write(ctx, path, data)
	if err != nil {
		return nil, WrapError("GenerateWrappedDataKey", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, WrapError("GenerateWrappedDataKey", fmt.Errorf("no data key returned"))
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return nil, WrapError("GenerateWrappedDataKey", fmt.Errorf("invalid ciphertext format"))
	}

	return &DataKeyResult{
		Ciphertext: ciphertext,
		KeyVersion: getInt(secret.Data, "key_version"),
	}, nil
}
