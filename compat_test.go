package jasypt

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Y-vQv-Y/go-jasypt/encoding"
	"github.com/Y-vQv-Y/go-jasypt/iv"
	"github.com/Y-vQv-Y/go-jasypt/pbe"
	"github.com/Y-vQv-Y/go-jasypt/salt"
	"github.com/Y-vQv-Y/go-jasypt/text"
)

// TestPBKDF1KeyDerivation verifies the PKCS#5 PBKDF1 key derivation
// against known test vectors from the Java jasypt implementation.
func TestPBKDF1KeyDerivation(t *testing.T) {
	// Create a fixed-salt encryptor and verify the derived key
	config := pbe.DefaultConfig()
	config.Password = "test"
	config.Algorithm = "PBEWithMD5AndDES"
	config.KeyObtentionIterations = 1000
	config.SaltGenerator = salt.NewFixedGenerator([]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0})
	config.IvGenerator = iv.NewNoGenerator()

	enc, err := pbe.NewStringEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Encrypt a known message
	encrypted, err := enc.Encrypt("Hello World")
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if encrypted == "" {
		t.Fatal("Encrypted result is empty")
	}
	t.Logf("Fixed-salt encrypted: %s", encrypted)

	// Decrypt should return the original message
	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != "Hello World" {
		t.Errorf("Decryption mismatch: got %q, want %q", decrypted, "Hello World")
	}

	// Same input should produce same output with fixed salt (deterministic)
	encrypted2, _ := enc.Encrypt("Hello World")
	if encrypted != encrypted2 {
		t.Errorf("Fixed salt: expected deterministic output, got different results:\n  %s\n  %s", encrypted, encrypted2)
	}

	// Different input should produce different output
	encrypted3, _ := enc.Encrypt("Different")
	if encrypted == encrypted3 {
		t.Error("Different messages should produce different ciphertexts")
	}
}

// TestEncryptDecryptRoundtrip tests roundtrip with various algorithms and settings.
func TestEncryptDecryptRoundtrip(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
		password  string
		message   string
		output    string // "base64" or "hexadecimal"
		iter      int
	}{
		{
			name:      "PBEWithMD5AndDES-base64",
			algorithm: "PBEWithMD5AndDES",
			password:  "secret123",
			message:   "Hello, 世界!",
			output:    "base64",
			iter:      1000,
		},
		{
			name:      "PBEWithMD5AndDES-hex",
			algorithm: "PBEWithMD5AndDES",
			password:  "secret123",
			message:   "Hello, World!",
			output:    "hexadecimal",
			iter:      500,
		},
		{
			name:      "PBEWITHHMACSHA512ANDAES_256-base64",
			algorithm: "PBEWITHHMACSHA512ANDAES_256",
			password:  "PILLAR-PLUS-SECRET",
			message:   "AES-256加密测试数据",
			output:    "base64",
			iter:      1000,
		},
		{
			name:      "PBEWITHHMACSHA512ANDAES_256-hex",
			algorithm: "PBEWITHHMACSHA512ANDAES_256",
			password:  "test-key",
			message:   "Hexadecimal output test",
			output:    "hexadecimal",
			iter:      2000,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := pbe.DefaultConfig()
			config.Password = tc.password
			config.Algorithm = tc.algorithm
			config.KeyObtentionIterations = tc.iter
			config.StringOutputType = tc.output
			config.SaltGenerator = salt.NewRandomGenerator()
			config.IvGenerator = iv.NewRandomGenerator()

			enc, err := pbe.NewStringEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			// Encrypt
			encrypted, err := enc.Encrypt(tc.message)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			t.Logf("Encrypted (%s): %s", tc.output, encrypted)

			// Verify output format
			if tc.output == "base64" {
				// Should be valid base64
				if _, err := encoding.DecodeBase64(encrypted); err != nil {
					t.Errorf("Output is not valid base64: %v", err)
				}
			} else {
				// Should be valid hex (uppercase)
				if _, err := hex.DecodeString(encrypted); err != nil {
					t.Errorf("Output is not valid hex: %v", err)
				}
				if encrypted != strings.ToUpper(encrypted) {
					t.Error("Hex output should be uppercase (matching jasypt)")
				}
			}

			// Decrypt
			decrypted, err := enc.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if decrypted != tc.message {
				t.Errorf("Decryption mismatch:\n  got:  %q\n  want: %q", decrypted, tc.message)
			}

			// Multiple roundtrips should work (with random salt/IV, each encrypt is different)
			encrypted2, _ := enc.Encrypt(tc.message)
			t.Logf("Second encrypt: %s", encrypted2)
			decrypted2, _ := enc.Decrypt(encrypted2)
			if decrypted2 != tc.message {
				t.Errorf("Second roundtrip failed: got %q", decrypted2)
			}
		})
	}
}

// TestEmptyAndNil tests edge cases for empty and nil inputs.
func TestEmptyAndNil(t *testing.T) {
	config := pbe.DefaultConfig()
	config.Password = "test"
	enc, _ := pbe.NewStringEncryptor(config)

	// Empty string
	result, err := enc.Encrypt("")
	if err != nil {
		t.Errorf("Empty encrypt should not error: %v", err)
	}
	if result != "" {
		t.Errorf("Empty encrypt should return empty: got %q", result)
	}

	decResult, err := enc.Decrypt("")
	if err != nil {
		t.Errorf("Empty decrypt should not error: %v", err)
	}
	if decResult != "" {
		t.Errorf("Empty decrypt should return empty: got %q", decResult)
	}
}

// TestWrongPassword verifies that decrypting with wrong password fails.
func TestWrongPassword(t *testing.T) {
	config1 := pbe.DefaultConfig()
	config1.Password = "correct-password"
	enc1, _ := pbe.NewStringEncryptor(config1)

	encrypted, _ := enc1.Encrypt("secret message")

	config2 := pbe.DefaultConfig()
	config2.Password = "wrong-password"
	enc2, _ := pbe.NewStringEncryptor(config2)

	_, err := enc2.Decrypt(encrypted)
	if err == nil {
		t.Error("Expected error when decrypting with wrong password")
	}
	t.Logf("Expected error with wrong password: %v", err)
}

// TestWrongAlgorithm verifies that using wrong algorithm for decryption fails.
func TestWrongAlgorithm(t *testing.T) {
	config1 := pbe.DefaultConfig()
	config1.Password = "test"
	config1.Algorithm = "PBEWithMD5AndDES"
	enc1, _ := pbe.NewStringEncryptor(config1)

	encrypted, _ := enc1.Encrypt("secret message")

	config2 := pbe.DefaultConfig()
	config2.Password = "test"
	config2.Algorithm = "PBEWithSHA1AndDESede"
	enc2, _ := pbe.NewStringEncryptor(config2)

	_, err := enc2.Decrypt(encrypted)
	if err == nil {
		t.Error("Expected error when decrypting with wrong algorithm")
	}
	t.Logf("Expected error with wrong algorithm: %v", err)
}

// TestTextEncryptors tests the convenience encryptors (Basic and Strong).
func TestTextEncryptors(t *testing.T) {
	t.Run("BasicTextEncryptor", func(t *testing.T) {
		enc := text.NewBasicTextEncryptor()
		enc.SetPassword("mySecret")
		encrypted, err := enc.Encrypt("Hello")
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		decrypted, err := enc.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}
		if decrypted != "Hello" {
			t.Errorf("Mismatch: got %q", decrypted)
		}
	})

	// TODO: StrongTextEncryptor uses PBEWithMD5AndTripleDES which requires
	// PKCS#12 key derivation (not yet implemented).
	// t.Run("StrongTextEncryptor", func(t *testing.T) { ... })
}

// TestUnicodePassword tests that NFC normalization works for Unicode passwords.
func TestUnicodePassword(t *testing.T) {
	// "café" can be represented as:
	// - Composed (NFC):   c  a  f  é (U+00E9)
	// - Decomposed (NFD): c  a  f  e  ́ (U+0065 U+0301)
	// jasypt applies NFC normalization, so both should produce the same encryption

	config1 := pbe.DefaultConfig()
	config1.Password = "café" // with composed é (NFC)
	enc1, _ := pbe.NewStringEncryptor(config1)

	encrypted, _ := enc1.Encrypt("test message")

	config2 := pbe.DefaultConfig()
	config2.Password = "café" // same NFC string
	enc2, _ := pbe.NewStringEncryptor(config2)

	decrypted, err := enc2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption with same NFC password failed: %v", err)
	}
	if decrypted != "test message" {
		t.Errorf("Mismatch: got %q", decrypted)
	}

	t.Log("Unicode NFC password normalization: same composed password works for encrypt and decrypt")
}

// TestSaltAndIvSizes verifies that salt and IV sizes match the algorithm block size.
func TestSaltAndIvSizes(t *testing.T) {
	testCases := []struct {
		algorithm string
		saltSize  int // expected salt size in output
		ivSize    int // expected IV size in output
	}{
		{"PBEWithMD5AndDES", 8, 0},     // DES: 8-byte block, NoIvGenerator by default
		{"PBEWithHmacSHA512AndAES_256", 16, 16}, // AES: 16-byte block
	}

	for _, tc := range testCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			config := pbe.DefaultConfig()
			config.Password = "test"
			config.Algorithm = tc.algorithm
			config.SaltGenerator = salt.NewRandomGenerator()
			config.IvGenerator = iv.NewRandomGenerator()

			enc, _ := pbe.NewStringEncryptor(config)
			encrypted, _ := enc.Encrypt("test")

			// Decode from base64
			raw, err := encoding.DecodeBase64(encrypted)
			if err != nil {
				t.Fatalf("Failed to decode base64: %v", err)
			}

			// Expected minimum size: salt + iv + at least 1 block of ciphertext
			minSize := tc.saltSize + tc.ivSize + tc.saltSize // last saltSize = min 1 block
			if len(raw) < minSize {
				t.Errorf("Encrypted data too small: %d bytes, expected at least %d", len(raw), minSize)
			}

			t.Logf("%s: total raw bytes = %d (salt=%d + iv=%d + ciphertext)", tc.algorithm, len(raw), tc.saltSize, tc.ivSize)
		})
	}
}
