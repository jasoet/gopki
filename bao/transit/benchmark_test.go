package transit

import (
	"context"
	"encoding/base64"
	"testing"
)

// BenchmarkEncrypt benchmarks single encryption operations.
func BenchmarkEncrypt(b *testing.B) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		b.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	plaintext := base64.StdEncoding.EncodeToString([]byte("benchmark data"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.Encrypt(ctx, "test-key", plaintext, nil)
	}
}

// BenchmarkBatchEncrypt benchmarks batch encryption with different sizes.
func BenchmarkBatchEncrypt(b *testing.B) {
	sizes := []int{10, 50, 100, 250}

	for _, size := range sizes {
		b.Run(string(rune(size)), func(b *testing.B) {
			client, _ := NewClient(&Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
			})
			defer client.Close()

			ctx := context.Background()
			items := make([]BatchEncryptItem, size)
			for i := 0; i < size; i++ {
				items[i] = BatchEncryptItem{
					Plaintext: base64.StdEncoding.EncodeToString([]byte("test data")),
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = client.EncryptBatch(ctx, "test-key", items)
			}
		})
	}
}

// BenchmarkSign benchmarks signature generation.
func BenchmarkSign(b *testing.B) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		b.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	data := base64.StdEncoding.EncodeToString([]byte("data to sign"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.Sign(ctx, "test-key", data, nil)
	}
}

// BenchmarkHMAC benchmarks HMAC generation.
func BenchmarkHMAC(b *testing.B) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		b.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	data := base64.StdEncoding.EncodeToString([]byte("data to hmac"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.HMAC(ctx, "test-key", data, nil)
	}
}

// BenchmarkHash benchmarks hash operations.
func BenchmarkHash(b *testing.B) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		b.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	data := base64.StdEncoding.EncodeToString([]byte("data to hash"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.Hash(ctx, data, nil)
	}
}

// BenchmarkGenerateRandom benchmarks random generation with different sizes.
func BenchmarkGenerateRandom(b *testing.B) {
	sizes := []int{16, 32, 64, 128}

	for _, size := range sizes {
		b.Run(string(rune(size)), func(b *testing.B) {
			client, _ := NewClient(&Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
			})
			defer client.Close()

			ctx := context.Background()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = client.GenerateRandom(ctx, size, nil)
			}
		})
	}
}

// BenchmarkBase64Encoding benchmarks base64 encoding overhead.
func BenchmarkBase64Encoding(b *testing.B) {
	data := []byte("test data for encoding")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = base64.StdEncoding.EncodeToString(data)
	}
}

// BenchmarkBase64Decoding benchmarks base64 decoding overhead.
func BenchmarkBase64Decoding(b *testing.B) {
	encoded := base64.StdEncoding.EncodeToString([]byte("test data for decoding"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = base64.StdEncoding.DecodeString(encoded)
	}
}
