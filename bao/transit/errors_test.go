package transit

import (
	"errors"
	"testing"
)

func TestIsAuthError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "ErrUnauthorized",
			err:  ErrUnauthorized,
			want: true,
		},
		{
			name: "ErrPermissionDenied",
			err:  ErrPermissionDenied,
			want: true,
		},
		{
			name: "wrapped ErrUnauthorized",
			err:  WrapError("Test", ErrUnauthorized),
			want: true,
		},
		{
			name: "other error",
			err:  ErrKeyNotFound,
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAuthError(tt.err); got != tt.want {
				t.Errorf("IsAuthError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "ErrKeyNotFound",
			err:  ErrKeyNotFound,
			want: true,
		},
		{
			name: "ErrKeyVersionNotFound",
			err:  ErrKeyVersionNotFound,
			want: true,
		},
		{
			name: "ErrMountNotFound",
			err:  ErrMountNotFound,
			want: true,
		},
		{
			name: "wrapped ErrKeyNotFound",
			err:  WrapError("GetKey", ErrKeyNotFound),
			want: true,
		},
		{
			name: "other error",
			err:  ErrUnauthorized,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFoundError(tt.err); got != tt.want {
				t.Errorf("IsNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsEncryptionError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "ErrInvalidCiphertext",
			err:  ErrInvalidCiphertext,
			want: true,
		},
		{
			name: "ErrContextRequired",
			err:  ErrContextRequired,
			want: true,
		},
		{
			name: "ErrConvergentEncryptionRequired",
			err:  ErrConvergentEncryptionRequired,
			want: true,
		},
		{
			name: "ErrInvalidBase64",
			err:  ErrInvalidBase64,
			want: true,
		},
		{
			name: "other error",
			err:  ErrKeyNotFound,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsEncryptionError(tt.err); got != tt.want {
				t.Errorf("IsEncryptionError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsBatchError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "ErrBatchTooLarge",
			err:  ErrBatchTooLarge,
			want: true,
		},
		{
			name: "ErrEmptyBatch",
			err:  ErrEmptyBatch,
			want: true,
		},
		{
			name: "other error",
			err:  ErrKeyNotFound,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsBatchError(tt.err); got != tt.want {
				t.Errorf("IsBatchError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsConnectionError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "ErrTimeout",
			err:  ErrTimeout,
			want: true,
		},
		{
			name: "ErrConnectionFailed",
			err:  ErrConnectionFailed,
			want: true,
		},
		{
			name: "ErrHealthCheckFailed",
			err:  ErrHealthCheckFailed,
			want: true,
		},
		{
			name: "other error",
			err:  ErrKeyNotFound,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsConnectionError(tt.err); got != tt.want {
				t.Errorf("IsConnectionError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWrapError(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		err       error
		wantNil   bool
		wantType  bool
	}{
		{
			name:      "wrap standard error",
			operation: "Encrypt",
			err:       errors.New("connection failed"),
			wantNil:   false,
			wantType:  true,
		},
		{
			name:      "wrap nil error",
			operation: "Encrypt",
			err:       nil,
			wantNil:   true,
			wantType:  false,
		},
		{
			name:      "wrap TransitError",
			operation: "CreateKey",
			err: &TransitError{
				Operation:  "OldOp",
				StatusCode: 404,
			},
			wantNil:  false,
			wantType: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WrapError(tt.operation, tt.err)

			if tt.wantNil && got != nil {
				t.Errorf("WrapError() = %v, want nil", got)
				return
			}

			if !tt.wantNil && got == nil {
				t.Error("WrapError() = nil, want non-nil")
				return
			}

			if tt.wantType {
				var transitErr *TransitError
				if !errors.As(got, &transitErr) {
					t.Errorf("WrapError() result is not TransitError")
				}

				if transitErr.Operation != tt.operation {
					t.Errorf("Operation = %v, want %v", transitErr.Operation, tt.operation)
				}
			}
		})
	}
}

func TestNewTransitError(t *testing.T) {
	err := NewTransitError("Encrypt", 400, []string{"bad request"}, ErrInvalidCiphertext)

	if err.Operation != "Encrypt" {
		t.Errorf("Operation = %v, want Encrypt", err.Operation)
	}

	if err.StatusCode != 400 {
		t.Errorf("StatusCode = %v, want 400", err.StatusCode)
	}

	if len(err.Errors) != 1 || err.Errors[0] != "bad request" {
		t.Errorf("Errors = %v, want [bad request]", err.Errors)
	}

	if err.Err != ErrInvalidCiphertext {
		t.Errorf("Err = %v, want ErrInvalidCiphertext", err.Err)
	}
}

func TestParseResponseError(t *testing.T) {
	tests := []struct {
		name         string
		operation    string
		statusCode   int
		errorsField  []interface{}
		wantContains string
	}{
		{
			name:         "single error message",
			operation:    "Encrypt",
			statusCode:   400,
			errorsField:  []interface{}{"invalid plaintext"},
			wantContains: "invalid plaintext",
		},
		{
			name:         "multiple error messages",
			operation:    "CreateKey",
			statusCode:   400,
			errorsField:  []interface{}{"key exists", "duplicate name"},
			wantContains: "key exists",
		},
		{
			name:         "no error messages",
			operation:    "GetKey",
			statusCode:   500,
			errorsField:  []interface{}{},
			wantContains: "HTTP 500",
		},
		{
			name:         "non-string error field",
			operation:    "Test",
			statusCode:   400,
			errorsField:  []interface{}{123, "valid error"},
			wantContains: "valid error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ParseResponseError(tt.operation, tt.statusCode, tt.errorsField)

			if err == nil {
				t.Fatal("ParseResponseError() = nil, want non-nil")
			}

			var transitErr *TransitError
			if !errors.As(err, &transitErr) {
				t.Fatal("result is not TransitError")
			}

			if transitErr.Operation != tt.operation {
				t.Errorf("Operation = %v, want %v", transitErr.Operation, tt.operation)
			}

			if transitErr.StatusCode != tt.statusCode {
				t.Errorf("StatusCode = %v, want %v", transitErr.StatusCode, tt.statusCode)
			}

			errStr := err.Error()
			if errStr == "" {
				t.Error("Error() returned empty string")
			}
		})
	}
}

func TestCheckStatusCode(t *testing.T) {
	tests := []struct {
		name       string
		operation  string
		statusCode int
		wantErr    bool
		wantErrIs  error
	}{
		{
			name:       "200 OK",
			operation:  "Test",
			statusCode: 200,
			wantErr:    false,
		},
		{
			name:       "204 No Content",
			operation:  "Test",
			statusCode: 204,
			wantErr:    false,
		},
		{
			name:       "401 Unauthorized",
			operation:  "Test",
			statusCode: 401,
			wantErr:    true,
			wantErrIs:  ErrUnauthorized,
		},
		{
			name:       "403 Forbidden",
			operation:  "Test",
			statusCode: 403,
			wantErr:    true,
			wantErrIs:  ErrPermissionDenied,
		},
		{
			name:       "404 Not Found",
			operation:  "Test",
			statusCode: 404,
			wantErr:    true,
		},
		{
			name:       "429 Rate Limit",
			operation:  "Test",
			statusCode: 429,
			wantErr:    true,
		},
		{
			name:       "500 Internal Server Error",
			operation:  "Test",
			statusCode: 500,
			wantErr:    true,
		},
		{
			name:       "503 Service Unavailable",
			operation:  "Test",
			statusCode: 503,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckStatusCode(tt.operation, tt.statusCode)

			if tt.wantErr && err == nil {
				t.Error("CheckStatusCode() = nil, want error")
				return
			}

			if !tt.wantErr && err != nil {
				t.Errorf("CheckStatusCode() = %v, want nil", err)
				return
			}

			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("CheckStatusCode() error = %v, want error containing %v", err, tt.wantErrIs)
			}

			if err != nil {
				var transitErr *TransitError
				if !errors.As(err, &transitErr) {
					t.Errorf("error is not TransitError: %v", err)
				}
			}
		})
	}
}
