package jwt

import (
	"fmt"
	"time"
)

// ValidationOptions configures claims validation
type ValidationOptions struct {
	// Validate expiration time (exp)
	ValidateExpiry bool

	// Validate not-before time (nbf)
	ValidateNotBefore bool

	// Validate issuer (iss)
	ValidateIssuer bool
	ExpectedIssuer string

	// Validate audience (aud)
	ValidateAudience bool
	ExpectedAudience []string

	// Clock skew tolerance (default: 60s)
	// Allows for clock differences between systems
	ClockSkew time.Duration

	// Now function (for testing - allows time injection)
	Now func() time.Time
}

// DefaultValidationOptions returns default validation options
func DefaultValidationOptions() *ValidationOptions {
	return &ValidationOptions{
		ValidateExpiry:    true,
		ValidateNotBefore: true,
		ClockSkew:         60 * time.Second,
		Now:               time.Now,
	}
}

// Validate validates claims according to the provided options
func (c *Claims) Validate(opts *ValidationOptions) error {
	if opts == nil {
		opts = DefaultValidationOptions()
	}

	// Set default values for nil fields
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ClockSkew == 0 {
		opts.ClockSkew = 60 * time.Second
	}

	now := opts.Now().Unix()
	skew := int64(opts.ClockSkew.Seconds())

	// Validate expiration (exp)
	if opts.ValidateExpiry && c.ExpiresAt != 0 {
		if now > c.ExpiresAt+skew {
			return ErrTokenExpired
		}
	}

	// Validate not-before (nbf)
	if opts.ValidateNotBefore && c.NotBefore != 0 {
		if now < c.NotBefore-skew {
			return ErrTokenNotYetValid
		}
	}

	// Validate issuer (iss)
	if opts.ValidateIssuer {
		if c.Issuer != opts.ExpectedIssuer {
			return fmt.Errorf("%w: got %q, want %q",
				ErrInvalidIssuer, c.Issuer, opts.ExpectedIssuer)
		}
	}

	// Validate audience (aud)
	if opts.ValidateAudience {
		if !c.hasAudience(opts.ExpectedAudience) {
			return fmt.Errorf("%w: %v", ErrInvalidAudience, c.Audience)
		}
	}

	return nil
}

// hasAudience checks if any expected audience is in claims
func (c *Claims) hasAudience(expected []string) bool {
	// If no expected audience specified, just check that some audience exists
	if len(expected) == 0 {
		return len(c.Audience) > 0
	}

	// Check if any expected audience matches
	for _, exp := range expected {
		for _, aud := range c.Audience {
			if aud == exp {
				return true
			}
		}
	}
	return false
}
