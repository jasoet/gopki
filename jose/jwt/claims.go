package jwt

import (
	"encoding/json"
	"time"
)

// Claims represents JWT claims as defined in RFC 7519 Section 4
type Claims struct {
	// Registered claims (RFC 7519 Section 4.1)
	Issuer    string   `json:"iss,omitempty"` // Issuer
	Subject   string   `json:"sub,omitempty"` // Subject
	Audience  Audience `json:"aud,omitempty"` // Audience (string or []string)
	ExpiresAt int64    `json:"exp,omitempty"` // Expiration time (Unix timestamp)
	NotBefore int64    `json:"nbf,omitempty"` // Not before (Unix timestamp)
	IssuedAt  int64    `json:"iat,omitempty"` // Issued at (Unix timestamp)
	JWTID     string   `json:"jti,omitempty"` // JWT ID

	// Custom claims (private/public)
	// Map allows for arbitrary additional claims
	Extra map[string]interface{} `json:"-"`
}

// Audience can be a single string or array of strings per RFC 7519
type Audience []string

// UnmarshalJSON handles both string and []string for audience claim
func (a *Audience) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as single string first
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}

	// Try as array of strings
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {
		return err
	}
	*a = Audience(multiple)
	return nil
}

// MarshalJSON returns single string if len==1, else array
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// MarshalJSON custom marshaling to include Extra claims
func (c *Claims) MarshalJSON() ([]byte, error) {
	// Use type alias to avoid infinite recursion
	type Alias Claims
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	// Marshal standard claims
	data, err := json.Marshal(aux)
	if err != nil {
		return nil, err
	}

	// If no extra claims, return as is
	if len(c.Extra) == 0 {
		return data, nil
	}

	// Merge extra claims into the JSON
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	for k, v := range c.Extra {
		m[k] = v
	}

	return json.Marshal(m)
}

// UnmarshalJSON custom unmarshaling to extract Extra claims
func (c *Claims) UnmarshalJSON(data []byte) error {
	// Use type alias to avoid infinite recursion
	type Alias Claims
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	// Unmarshal standard claims
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// Extract all claims
	var all map[string]interface{}
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}

	// Remove registered claims to get extras
	registered := map[string]bool{
		"iss": true, "sub": true, "aud": true,
		"exp": true, "nbf": true, "iat": true, "jti": true,
	}

	c.Extra = make(map[string]interface{})
	for k, v := range all {
		if !registered[k] {
			c.Extra[k] = v
		}
	}

	return nil
}

// NewClaims creates a new Claims instance with current timestamp
func NewClaims() *Claims {
	now := time.Now().Unix()
	return &Claims{
		IssuedAt: now,
		Extra:    make(map[string]interface{}),
	}
}

// SetExpiration sets expiration time from duration
func (c *Claims) SetExpiration(d time.Duration) {
	c.ExpiresAt = time.Now().Add(d).Unix()
}

// SetNotBefore sets not-before time from duration
func (c *Claims) SetNotBefore(d time.Duration) {
	c.NotBefore = time.Now().Add(d).Unix()
}

// IsExpired checks if the token is expired
func (c *Claims) IsExpired() bool {
	if c.ExpiresAt == 0 {
		return false
	}
	return time.Now().Unix() > c.ExpiresAt
}

// IsNotYetValid checks if the token is not yet valid
func (c *Claims) IsNotYetValid() bool {
	if c.NotBefore == 0 {
		return false
	}
	return time.Now().Unix() < c.NotBefore
}
