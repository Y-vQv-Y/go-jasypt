// Package iv provides initialization vector (IV) generators for PBE encryption,
// mirroring the org.jasypt.iv package in the Java implementation (added in jasypt 1.9.3).
package iv

import "crypto/rand"

// Generator is the interface for all IV generators.
// Every implementation must be thread-safe.
type Generator interface {
	// GenerateIv returns a new IV of the specified length in bytes.
	GenerateIv(lengthBytes int) []byte

	// IncludePlainIvInEncryptionResults determines if the unencrypted IV
	// should be prepended to encryption results so it can be used for decryption.
	IncludePlainIvInEncryptionResults() bool
}

// RandomGenerator generates random IVs using crypto/rand.
// Corresponds to org.jasypt.iv.RandomIvGenerator.
type RandomGenerator struct{}

// NewRandomGenerator creates a new RandomGenerator.
func NewRandomGenerator() *RandomGenerator {
	return &RandomGenerator{}
}

func (g *RandomGenerator) GenerateIv(lengthBytes int) []byte {
	iv := make([]byte, lengthBytes)
	if _, err := rand.Read(iv); err != nil {
		panic("iv: failed to generate random bytes: " + err.Error())
	}
	return iv
}

func (g *RandomGenerator) IncludePlainIvInEncryptionResults() bool {
	return true
}

// NoGenerator always returns an empty IV (length 0).
// This is the default IV generator in jasypt for backward compatibility.
// Corresponds to org.jasypt.iv.NoIvGenerator.
type NoGenerator struct{}

// NewNoGenerator creates a new NoGenerator.
func NewNoGenerator() *NoGenerator {
	return &NoGenerator{}
}

func (g *NoGenerator) GenerateIv(lengthBytes int) []byte {
	return []byte{}
}

func (g *NoGenerator) IncludePlainIvInEncryptionResults() bool {
	return false
}

// FixedGenerator returns the same IV every time.
// Corresponds to org.jasypt.iv.FixedIvGenerator.
type FixedGenerator struct {
	iv []byte
}

// NewFixedGenerator creates a FixedGenerator that always returns the given IV bytes.
func NewFixedGenerator(iv []byte) *FixedGenerator {
	return &FixedGenerator{iv: append([]byte{}, iv...)}
}

func (g *FixedGenerator) GenerateIv(lengthBytes int) []byte {
	result := make([]byte, lengthBytes)
	copy(result, g.iv)
	return result
}

func (g *FixedGenerator) IncludePlainIvInEncryptionResults() bool {
	return false
}
