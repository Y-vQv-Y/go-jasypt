package pbe

import (
	"fmt"

	"github.com/Y-vQv-Y/go-jasypt/iv"
	"github.com/Y-vQv-Y/go-jasypt/salt"
)

// Config holds the configuration for a PBE encryptor,
// mirroring org.jasypt.encryption.pbe.config.PBEConfig.
type Config struct {
	// Algorithm is the PBE algorithm name, e.g. "PBEWithMD5AndDES", "PBEWITHHMACSHA512ANDAES_256".
	// Default: "PBEWithMD5AndDES"
	Algorithm string

	// Password is the encryption password (required, no default).
	Password string

	// KeyObtentionIterations is the number of hashing iterations for key derivation.
	// Default: 1000
	KeyObtentionIterations int

	// SaltGenerator generates salt bytes for key derivation.
	// Default: RandomSaltGenerator
	SaltGenerator salt.Generator

	// IvGenerator generates initialization vector bytes.
	// Default: NoIvGenerator (for backward compatibility with jasypt < 1.9.3)
	IvGenerator iv.Generator

	// StringOutputType is either "base64" or "hexadecimal".
	// Default: "base64"
	StringOutputType string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Algorithm:              "PBEWithMD5AndDES",
		KeyObtentionIterations: 1000,
		SaltGenerator:          salt.NewRandomGenerator(),
		IvGenerator:            iv.NewNoGenerator(),
		StringOutputType:       "base64",
	}
}

// Validate checks that the configuration has all required fields.
// Note: Password is NOT required at construction time (jasypt allows
// setting password after construction), but IS required at Encrypt/Decrypt time.
func (c *Config) Validate() error {
	if c.Algorithm == "" {
		c.Algorithm = "PBEWithMD5AndDES"
	}
	if c.KeyObtentionIterations <= 0 {
		c.KeyObtentionIterations = 1000
	}
	if c.SaltGenerator == nil {
		c.SaltGenerator = salt.NewRandomGenerator()
	}
	if c.IvGenerator == nil {
		c.IvGenerator = iv.NewNoGenerator()
	}
	if c.StringOutputType == "" {
		c.StringOutputType = "base64"
	}

	params := getAlgorithmParams(c.Algorithm)
	if params == nil {
		return fmt.Errorf("pbe: unsupported algorithm: %s", c.Algorithm)
	}
	_ = params

	return nil
}

// requirePassword checks that a password is set, returning an error if not.
func (c *Config) requirePassword() error {
	if c.Password == "" {
		return fmt.Errorf("pbe: password is required but not set")
	}
	return nil
}
