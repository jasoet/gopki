//go:build compatibility

package bao_test

import (
	"testing"
)

func TestPKCS12_Bao_Compatibility(t *testing.T) {
	t.Skip("TODO: Fix PKCS#12 API - requires investigation of CreateP12 and ParseP12 correct usage patterns")
}
