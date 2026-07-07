// Package salt provides salt generators for PBE encryption,
// mirroring the org.jasypt.salt package in the Java implementation.
package salt

// Generator is the interface for all salt generators.
// Every implementation must be thread-safe.
type Generator interface {
	// GenerateSalt returns a new salt of the specified length in bytes.
	GenerateSalt(lengthBytes int) []byte

	// IncludePlainSaltInEncryptionResults determines if the unencrypted salt
	// should be prepended to encryption results so it can be used for decryption.
	IncludePlainSaltInEncryptionResults() bool
}

// RandomGenerator generates random salts using crypto/rand.
// Corresponds to org.jasypt.salt.RandomSaltGenerator.
type RandomGenerator struct{}

// NewRandomGenerator creates a new RandomGenerator.
func NewRandomGenerator() *RandomGenerator {
	return &RandomGenerator{}
}

func (g *RandomGenerator) GenerateSalt(lengthBytes int) []byte {
	salt := make([]byte, lengthBytes)
	// crypto/rand.Read is guaranteed to fill the buffer entirely
	if _, err := randRead(salt); err != nil {
		panic("salt: failed to generate random bytes: " + err.Error())
	}
	return salt
}

func (g *RandomGenerator) IncludePlainSaltInEncryptionResults() bool {
	return true
}

// FixedGenerator returns the same salt every time.
// Corresponds to org.jasypt.salt.FixedByteArraySaltGenerator.
type FixedGenerator struct {
	salt []byte
}

// NewFixedGenerator creates a FixedGenerator that always returns the given salt bytes.
func NewFixedGenerator(salt []byte) *FixedGenerator {
	return &FixedGenerator{salt: append([]byte{}, salt...)}
}

func (g *FixedGenerator) GenerateSalt(lengthBytes int) []byte {
	// Return a copy of the stored salt, truncated or extended to match the requested length
	result := make([]byte, lengthBytes)
	copy(result, g.salt)
	return result
}

func (g *FixedGenerator) IncludePlainSaltInEncryptionResults() bool {
	return false
}

// ZeroGenerator always returns zeros.
// Corresponds to org.jasypt.salt.ZeroSaltGenerator.
type ZeroGenerator struct{}

// NewZeroGenerator creates a new ZeroGenerator.
func NewZeroGenerator() *ZeroGenerator {
	return &ZeroGenerator{}
}

func (g *ZeroGenerator) GenerateSalt(lengthBytes int) []byte {
	return make([]byte, lengthBytes)
}

func (g *ZeroGenerator) IncludePlainSaltInEncryptionResults() bool {
	return false
}
