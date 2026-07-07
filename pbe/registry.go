package pbe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha512"
	"hash"
)

// algorithmParams defines the cryptographic parameters for a PBE algorithm.
type algorithmParams struct {
	// KeyDerivation is either "PBKDF1" or "PBKDF2".
	keyDerivation string

	// HashName is the name of the hash function: "MD5", "SHA-1", "SHA-256", "SHA-512".
	hashName string

	// hashFunc returns a new hash.Hash instance.
	hashFunc func() hash.Hash

	// cipherFunc returns a new cipher.Block from a key.
	cipherFunc func(key []byte) (cipher.Block, error)

	// keyLen is the length of the derived key in bytes.
	keyLen int

	// blockSize is the cipher block size, used for salt and IV sizes.
	blockSize int

	// passwordEncoding is "CHAR_TRUNC" (SunJCE) or "UTF8" (BouncyCastle).
	passwordEncoding string

	// ivFromDerivation: if true, the IV is derived internally from the key derivation
	// (PBKDF1 style, e.g., PBEWithMD5AndDES). If false, the IV is provided externally
	// through the IvGenerator (PBKDF2 style, e.g., PBEWithHmacSHA512AndAES_256).
	ivFromDerivation bool

	// needsBC: true if this algorithm requires BouncyCastle provider in Java.
	// In Go, we implement it directly, so this is informational.
	needsBC bool
}

// registry maps algorithm names (case-insensitive lookup) to their parameters.
// Supported algorithms match those commonly used with jasypt.
var registry = map[string]*algorithmParams{
	// Built-in JVM algorithms (SunJCE)
	"PBEWITHMD5ANDDES": {
		keyDerivation:    "PBKDF1",
		hashName:         "MD5",
		hashFunc:         md5.New,
		cipherFunc:       des.NewCipher,
		keyLen:           8, // 56-bit DES key
		blockSize:        8, // DES block size
		passwordEncoding: "CHAR_TRUNC",
		ivFromDerivation: true,
		needsBC:          false,
	},

	"PBEWITHSHA1ANDDESEDE": {
		keyDerivation:    "PBKDF1",
		hashName:         "SHA-1",
		hashFunc:         sha1.New,
		cipherFunc:       des.NewTripleDESCipher,
		keyLen:           24, // 3DES key (3 × 8 bytes)
		blockSize:        8,  // 3DES block size (same as DES)
		passwordEncoding: "CHAR_TRUNC",
		ivFromDerivation: true,
		needsBC:          false,
	},

	// BouncyCastle algorithms
	"PBEWITHHMACSHA512ANDAES_256": {
		keyDerivation:    "PBKDF2",
		hashName:         "SHA-512",
		hashFunc:         sha512.New,
		cipherFunc:       aes.NewCipher,
		keyLen:           32, // AES-256 key
		blockSize:        16, // AES block size
		passwordEncoding: "UTF8",
		ivFromDerivation: false,
		needsBC:          true,
	},
}

// normalizeAlgorithmName normalizes the algorithm name for case-insensitive lookup.
func normalizeAlgorithmName(name string) string {
	// Simple uppercase normalization for lookup.
	// The registry keys are in uppercase.
	upper := make([]byte, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		upper[i] = c
	}
	return string(upper)
}

// getAlgorithmParams returns the parameters for the named algorithm, or nil if unsupported.
func getAlgorithmParams(algorithm string) *algorithmParams {
	return registry[normalizeAlgorithmName(algorithm)]
}
