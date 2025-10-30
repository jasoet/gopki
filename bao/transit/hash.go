package transit

import (
	"context"
	"fmt"
)

// HashOptions contains options for hash operations.
type HashOptions struct {
	// Algorithm specifies the hash algorithm to use.
	// Valid values: "sha2-224", "sha2-256" (default), "sha2-384", "sha2-512",
	// "sha3-224", "sha3-256", "sha3-384", "sha3-512".
	Algorithm HashAlgorithm

	// Format specifies the output format.
	// Valid values: "hex" (default), "base64".
	Format string
}

// HashResult contains the result of a hash operation.
type HashResult struct {
	// Sum is the hash value (encoded as specified).
	Sum string
}

// Hash generates a cryptographic hash of the input data.
// Input should be base64-encoded.
//
// This endpoint is provided as a convenience for clients that need to
// compute hashes of data for use with other Transit operations (e.g.,
// signing prehashed data).
//
// Example:
//
//	input := base64.StdEncoding.EncodeToString([]byte("data to hash"))
//	result, err := client.Hash(ctx, input, &HashOptions{
//	    Algorithm: HashSHA2_256,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(result.Sum)
func (c *Client) Hash(ctx context.Context, input string, opts *HashOptions) (*HashResult, error) {
	if input == "" {
		return nil, fmt.Errorf("input cannot be empty")
	}

	path := "hash"

	data := map[string]interface{}{
		"input": input,
	}

	if opts != nil {
		if opts.Algorithm != "" {
			data["algorithm"] = string(opts.Algorithm)
		}
		if opts.Format != "" {
			data["format"] = opts.Format
		}
	}

	secret, err := c.write(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("transit Hash: %w", err)
	}

	result := &HashResult{}

	if sum, ok := secret.Data["sum"].(string); ok {
		result.Sum = sum
	} else {
		return nil, fmt.Errorf("unexpected response format from hash endpoint")
	}

	return result, nil
}

// HashWithAlgorithm is a convenience wrapper that hashes data with a specific algorithm.
func (c *Client) HashWithAlgorithm(ctx context.Context, input string, algorithm HashAlgorithm) (string, error) {
	result, err := c.Hash(ctx, input, &HashOptions{
		Algorithm: algorithm,
	})
	if err != nil {
		return "", err
	}
	return result.Sum, nil
}
