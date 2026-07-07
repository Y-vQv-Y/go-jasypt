package pbe

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/Y-vQv-Y/go-jasypt/encoding"
	"github.com/Y-vQv-Y/go-jasypt/salt"
	"github.com/Y-vQv-Y/go-jasypt/util"
)

// ByteEncryptor is the core PBE byte-level encryptor.
// It mirrors org.jasypt.encryption.pbe.StandardPBEByteEncryptor.
//
// Thread-safety: ByteEncryptor is NOT thread-safe. Use a PooledEncryptor
// or sync.Mutex if concurrent access is needed.
type ByteEncryptor struct {
	config  *Config
	params  *algorithmParams
	key     []byte // derived encryption key
	derived []byte // for PBKDF1: full derived output (key + IV)

	// Pre-computed for fixed salt optimization
	useFixedSalt bool
	fixedSalt    []byte
}

// NewByteEncryptor creates a new ByteEncryptor from the given configuration.
// The encryptor is not initialized until Encrypt() or Decrypt() is called.
func NewByteEncryptor(config *Config) (*ByteEncryptor, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	params := getAlgorithmParams(config.Algorithm)
	if params == nil {
		return nil, fmt.Errorf("pbe: unsupported algorithm: %s", config.Algorithm)
	}

	e := &ByteEncryptor{
		config: config,
		params: params,
	}

	// Check for fixed salt optimization
	if fixedGen, ok := config.SaltGenerator.(*salt.FixedGenerator); ok {
		if _, isNoIv := config.IvGenerator.(interface{ IncludePlainIvInEncryptionResults() bool }); isNoIv {
			e.useFixedSalt = true
			e.fixedSalt = fixedGen.GenerateSalt(params.blockSize)
			// Pre-derive key with fixed salt
			e.deriveKey(e.fixedSalt)
		}
	}

	return e, nil
}

// deriveKey derives the encryption key from the password and salt.
// For PBKDF1, it also stores the full derived output for IV extraction.
func (e *ByteEncryptor) deriveKey(saltBytes []byte) {
	// Apply NFC normalization to password (same as jasypt)
	normalizedPwd := util.NormalizeToNfc(e.config.Password)

	// Convert password to bytes according to algorithm's encoding
	pwdBytes := passwordToBytes(normalizedPwd, e.params.passwordEncoding)

	hashFunc := e.params.hashFunc

	if e.params.keyDerivation == "PBKDF1" {
		// For PBKDF1, derive enough bytes for key + IV
		// The total output is limited by the hash output size
		totalLen := e.params.keyLen + e.params.blockSize
		hashSize := hashFunc().Size()
		if totalLen > hashSize {
			totalLen = hashSize
		}
		e.derived = deriveKeyPBKDF1(pwdBytes, saltBytes, e.config.KeyObtentionIterations, hashFunc, totalLen)
		// Key is min(keyLen, len(derived)) — this is important for algorithms
		// where PBKDF1 hash output is smaller than the required key length.
		actualKeyLen := e.params.keyLen
		if actualKeyLen > len(e.derived) {
			actualKeyLen = len(e.derived)
		}
		e.key = make([]byte, e.params.keyLen)
		copy(e.key, e.derived[:actualKeyLen])
	} else {
		// PBKDF2
		e.key = deriveKeyPBKDF2(pwdBytes, saltBytes, e.config.KeyObtentionIterations, e.params.keyLen, hashFunc)
	}
}

// getIv returns the IV for encryption/decryption.
// For PBKDF1 algorithms, the IV is derived from the key derivation.
// For PBKDF2 algorithms, the IV comes from the IvGenerator.
func (e *ByteEncryptor) getIv(ivFromGenerator []byte) []byte {
	if e.params.ivFromDerivation {
		// PBKDF1: IV comes from the derived bytes (after the key)
		if e.derived != nil && len(e.derived) > e.params.keyLen {
			iv := make([]byte, e.params.blockSize)
			copy(iv, e.derived[e.params.keyLen:])
			return iv
		}
		// If no derived bytes, generate zeros
		return make([]byte, e.params.blockSize)
	}
	// PBKDF2: IV from the generator
	if len(ivFromGenerator) > 0 {
		return ivFromGenerator
	}
	return make([]byte, e.params.blockSize)
}

// Encrypt encrypts a byte array message.
// The output format is: [salt?] + [iv?] + [ciphertext]
func (e *ByteEncryptor) Encrypt(message []byte) ([]byte, error) {
	if message == nil {
		return nil, nil
	}

	// Validate password is set
	if e.config.Password == "" {
		return nil, fmt.Errorf("pbe: password is required but not set")
	}

	// 1. Generate salt
	saltBytes := e.config.SaltGenerator.GenerateSalt(e.params.blockSize)

	// 2. Generate IV (from generator)
	ivBytes := e.config.IvGenerator.GenerateIv(e.params.blockSize)

	// 3. Derive key (if not already pre-derived with fixed salt)
	if !e.useFixedSalt {
		e.deriveKey(saltBytes)
	}

	// 4. Get the actual IV to use for the cipher
	actualIv := e.getIv(ivBytes)

	// 5. Create cipher and encrypt
	block, err := e.params.cipherFunc(e.key)
	if err != nil {
		return nil, fmt.Errorf("pbe: failed to create cipher: %w", err)
	}

	// Apply PKCS7 padding (equivalent to Java's PKCS5Padding)
	paddedMessage := pkcs7Pad(message, block.BlockSize())

	// CBC mode encryption
	cbcCipher := cipher.NewCBCEncrypter(block, actualIv)
	encrypted := make([]byte, len(paddedMessage))
	cbcCipher.CryptBlocks(encrypted, paddedMessage)

	// 6. Build output: [salt?] + [iv?] + [ciphertext]
	// Order must match Java implementation:
	//   First prepend IV, then prepend salt ON TOP of that
	//   So final order = [salt] + [iv] + [ciphertext]
	var result []byte

	if e.config.IvGenerator.IncludePlainIvInEncryptionResults() {
		result = append(ivBytes, encrypted...)
	} else {
		result = encrypted
	}

	if e.config.SaltGenerator.IncludePlainSaltInEncryptionResults() {
		result = append(saltBytes, result...)
	}

	return result, nil
}

// Decrypt decrypts a byte array message.
// The input format is: [salt?] + [iv?] + [ciphertext]
func (e *ByteEncryptor) Decrypt(encryptedMessage []byte) ([]byte, error) {
	if encryptedMessage == nil {
		return nil, nil
	}

	// Validate password is set
	if e.config.Password == "" {
		return nil, fmt.Errorf("pbe: password is required but not set")
	}

	// 1. Extract salt from the beginning (if present)
	var saltBytes []byte
	kernel := encryptedMessage

	if e.config.SaltGenerator.IncludePlainSaltInEncryptionResults() {
		if len(kernel) < e.params.blockSize {
			return nil, fmt.Errorf("pbe: encrypted message too short for salt")
		}
		saltBytes = make([]byte, e.params.blockSize)
		copy(saltBytes, kernel[:e.params.blockSize])
		kernel = kernel[e.params.blockSize:]
	} else {
		saltBytes = e.config.SaltGenerator.GenerateSalt(e.params.blockSize)
	}

	// 2. Extract IV from the beginning of kernel (if present)
	var ivBytes []byte
	finalKernel := kernel

	if e.config.IvGenerator.IncludePlainIvInEncryptionResults() {
		if len(kernel) < e.params.blockSize {
			return nil, fmt.Errorf("pbe: encrypted message too short for IV")
		}
		ivBytes = make([]byte, e.params.blockSize)
		copy(ivBytes, kernel[:e.params.blockSize])
		finalKernel = kernel[e.params.blockSize:]
	} else {
		ivBytes = e.config.IvGenerator.GenerateIv(e.params.blockSize)
	}

	// 3. Derive key from salt
	e.deriveKey(saltBytes)

	// 4. Get the actual IV for the cipher
	actualIv := e.getIv(ivBytes)

	// 5. Create cipher and decrypt
	block, err := e.params.cipherFunc(e.key)
	if err != nil {
		return nil, fmt.Errorf("pbe: failed to create cipher: %w", err)
	}

	if len(finalKernel)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("pbe: ciphertext is not a multiple of block size")
	}

	cbcCipher := cipher.NewCBCDecrypter(block, actualIv)
	decrypted := make([]byte, len(finalKernel))
	cbcCipher.CryptBlocks(decrypted, finalKernel)

	// 6. Remove PKCS7 padding
	message, err := pkcs7Unpad(decrypted)
	if err != nil {
		return nil, fmt.Errorf("pbe: decryption failed (wrong password or corrupted data): %w", err)
	}

	return message, nil
}

// pkcs7Pad applies PKCS#7 padding (identical to PKCS#5 for block sizes >= 8).
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7Unpad removes PKCS#7 padding.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pkcs7: data is empty")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return nil, fmt.Errorf("pkcs7: invalid padding byte: %d", padding)
	}
	// Verify all padding bytes
	for i := 0; i < padding; i++ {
		if data[len(data)-1-i] != byte(padding) {
			return nil, fmt.Errorf("pkcs7: invalid padding block")
		}
	}
	return data[:len(data)-padding], nil
}

// randomBytes generates cryptographically secure random bytes.
// Used for generating random salts and IVs.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("pbe: failed to read random bytes: " + err.Error())
	}
	return b
}

// ByteEncryptor //

// --- Convenience: encrypt/decrypt with encoding ---

// EncryptAndEncode encrypts bytes and encodes the result as a string (Base64 or Hex).
func (e *ByteEncryptor) EncryptAndEncode(message []byte, outputType string) (string, error) {
	encrypted, err := e.Encrypt(message)
	if err != nil {
		return "", err
	}
	if outputType == "hexadecimal" || outputType == "hex" {
		return encoding.EncodeHex(encrypted), nil
	}
	return encoding.EncodeBase64(encrypted), nil
}

// DecodeAndDecrypt decodes a string and decrypts it.
func (e *ByteEncryptor) DecodeAndDecrypt(encoded string, outputType string) ([]byte, error) {
	var encrypted []byte
	var err error
	if outputType == "hexadecimal" || outputType == "hex" {
		encrypted, err = encoding.DecodeHex(encoded)
	} else {
		encrypted, err = encoding.DecodeBase64(encoded)
	}
	if err != nil {
		return nil, fmt.Errorf("pbe: failed to decode: %w", err)
	}
	return e.Decrypt(encrypted)
}
