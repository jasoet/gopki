//go:build compatibility

package bao_test

import (
	"testing"
)

func TestSigning_Bao_Compatibility(t *testing.T) {
	t.Skip("TODO: Fix signing API - requires investigation of SignDocument/VerifySignature patterns and detached signature APIs")
}
