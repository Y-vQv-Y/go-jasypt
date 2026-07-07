package pbe

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// deriveKeyPBKDF1 derives a key using the PKCS#5 PBKDF1 scheme.
// This is used by older PBE algorithms like PBEWithMD5AndDES.
//
// The algorithm:
//
//	hash = Hash(password || salt)
//	for i = 1; i < iterations; i++ {
//	    hash = Hash(hash)
//	}
//	return hash[0:keyLen]
//
// Note: In PBKDF1, the total derived output cannot exceed the hash output size.
// For DES: 16 bytes (8 key + 8 IV) from MD5's 16-byte output.
func deriveKeyPBKDF1(password, salt []byte, iterations int, h func() hash.Hash, keyLen int) []byte {
	hasher := h()
	hasher.Write(password)
	hasher.Write(salt)
	derived := hasher.Sum(nil)

	for i := 1; i < iterations; i++ {
		hasher.Reset()
		hasher.Write(derived)
		derived = hasher.Sum(nil)
	}

	if keyLen > len(derived) {
		keyLen = len(derived)
	}
	result := make([]byte, keyLen)
	copy(result, derived)
	return result
}

// deriveKeyPBKDF2 derives a key using the PKCS#5 PBKDF2 scheme.
// This is used by newer PBE algorithms like PBEWithHmacSHA512AndAES_256.
func deriveKeyPBKDF2(password, salt []byte, iterations, keyLen int, h func() hash.Hash) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, h)
}

// passwordToBytes converts a password string to bytes according to the specified encoding.
// "CHAR_TRUNC": each rune truncated to its lower 8 bits (Java SunJCE behavior)
// "UTF8": standard UTF-8 encoding (BouncyCastle PKCS5PasswordToBytes behavior)
// Both are applied AFTER NFC normalization (which is done by the caller).
func passwordToBytes(password string, encoding string) []byte {
	switch encoding {
	case "CHAR_TRUNC":
		// Java's SunJCE PBE: each char lower 8 bits
		runes := []rune(password)
		result := make([]byte, len(runes))
		for i, r := range runes {
			result[i] = byte(r & 0xFF)
		}
		return result
	default: // "UTF8"
		return []byte(password)
	}
}

// hashByName returns a hash constructor for the given algorithm name.
// Used to map algorithm names like "MD5", "SHA-512" to Go hash functions.
func hashByName(name string) func() hash.Hash {
	switch name {
	case "MD5":
		return md5.New
	case "SHA-1":
		return sha1.New
	case "SHA-256":
		return sha256.New
	case "SHA-512":
		return sha512.New
	default:
		return nil
	}
}
