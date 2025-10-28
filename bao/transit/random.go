package transit

import (
	"context"
	"fmt"
)

// RandomSource specifies the source of entropy for random generation.
type RandomSource string

const (
	// RandomSourcePlatform uses the platform's entropy source (e.g., /dev/urandom).
	RandomSourcePlatform RandomSource = "platform"

	// RandomSourceSeal uses the seal's entropy source.
	RandomSourceSeal RandomSource = "seal"

	// RandomSourceAll uses entropy from both platform and seal.
	RandomSourceAll RandomSource = "all"
)

// RandomFormat specifies the output format for random data.
type RandomFormat string

const (
	// RandomFormatBase64 returns base64-encoded random data.
	RandomFormatBase64 RandomFormat = "base64"

	// RandomFormatHex returns hex-encoded random data.
	RandomFormatHex RandomFormat = "hex"
)

// RandomOptions contains options for random data generation.
type RandomOptions struct {
	// Source specifies the entropy source.
	// Valid values: "platform" (default), "seal", "all".
	Source RandomSource

	// Format specifies the output encoding.
	// Valid values: "base64" (default), "hex".
	Format RandomFormat
}

// RandomResult contains the generated random data.
type RandomResult struct {
	// RandomBytes is the generated random data (encoded as specified).
	RandomBytes string
}

// GenerateRandom generates cryptographically secure random bytes.
// The bytes parameter specifies how many random bytes to generate.
// The returned data is encoded according to the format option (base64 by default).
//
// Example:
//
//	// Generate 32 random bytes (base64-encoded)
//	result, err := client.GenerateRandom(ctx, 32, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(result.RandomBytes)
//
//	// Generate 16 random bytes (hex-encoded)
//	result, err := client.GenerateRandom(ctx, 16, &RandomOptions{
//	    Format: RandomFormatHex,
//	})
func (c *Client) GenerateRandom(ctx context.Context, bytes int, opts *RandomOptions) (*RandomResult, error) {
	if bytes <= 0 {
		return nil, fmt.Errorf("bytes must be greater than 0")
	}

	// OpenBao has a practical limit on random bytes generation
	// Typical limit is around 1MB (1048576 bytes)
	if bytes > 1048576 {
		return nil, fmt.Errorf("bytes cannot exceed 1048576 (1MB)")
	}

	path := fmt.Sprintf("random/%d", bytes)

	data := make(map[string]interface{})

	if opts != nil {
		if opts.Source != "" {
			data["source"] = string(opts.Source)
		}
		if opts.Format != "" {
			data["format"] = string(opts.Format)
		}
	}

	// Use write for POST request (OpenBao uses POST for random generation)
	secret, err := c.write(ctx, path, data)

	if err != nil {
		return nil, fmt.Errorf("transit GenerateRandom: %w", err)
	}

	result := &RandomResult{}

	// The response field might be "random_bytes" or just "data"
	if randomBytes, ok := secret.Data["random_bytes"].(string); ok {
		result.RandomBytes = randomBytes
	} else if data, ok := secret.Data["data"].(string); ok {
		result.RandomBytes = data
	} else {
		return nil, fmt.Errorf("unexpected response format from random endpoint")
	}

	return result, nil
}

// GenerateRandomBytes is a convenience wrapper that generates random bytes
// and returns them in base64 encoding (the default format).
func (c *Client) GenerateRandomBytes(ctx context.Context, bytes int) (string, error) {
	result, err := c.GenerateRandom(ctx, bytes, nil)
	if err != nil {
		return "", err
	}
	return result.RandomBytes, nil
}

// GenerateRandomHex is a convenience wrapper that generates random bytes
// and returns them in hex encoding.
func (c *Client) GenerateRandomHex(ctx context.Context, bytes int) (string, error) {
	result, err := c.GenerateRandom(ctx, bytes, &RandomOptions{
		Format: RandomFormatHex,
	})
	if err != nil {
		return "", err
	}
	return result.RandomBytes, nil
}
