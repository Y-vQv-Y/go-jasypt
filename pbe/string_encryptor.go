package pbe

import (
	"fmt"

	"github.com/go-jasypt/jasypt/encoding"
)

// StringEncryptor encrypts and decrypts string messages.
// It wraps ByteEncryptor with UTF-8 encoding and Base64/Hex output encoding.
// This mirrors org.jasypt.encryption.pbe.StandardPBEStringEncryptor.
//
// Thread-safety: StringEncryptor is NOT thread-safe.
type StringEncryptor struct {
	byteEncryptor *ByteEncryptor
	outputType    string // "base64" or "hexadecimal"
	isBase64      bool
}

// NewStringEncryptor creates a new StringEncryptor from the given configuration.
func NewStringEncryptor(config *Config) (*StringEncryptor, error) {
	be, err := NewByteEncryptor(config)
	if err != nil {
		return nil, err
	}

	outputType := config.StringOutputType
	if outputType == "" {
		outputType = "base64"
	}

	return &StringEncryptor{
		byteEncryptor: be,
		outputType:    outputType,
		isBase64:      outputType == "base64",
	}, nil
}

// Encrypt encrypts a string message and returns the Base64/Hex encoded result.
// The input string is converted to UTF-8 bytes before encryption (matching
// jasypt's MESSAGE_CHARSET = "UTF-8").
func (e *StringEncryptor) Encrypt(message string) (string, error) {
	if message == "" {
		return "", nil
	}

	// String → UTF-8 bytes (jasypt uses MESSAGE_CHARSET = "UTF-8")
	messageBytes := []byte(message)

	// Encrypt
	encrypted, err := e.byteEncryptor.Encrypt(messageBytes)
	if err != nil {
		return "", fmt.Errorf("pbe: encryption failed: %w", err)
	}

	// Encode as Base64 or Hex (jasypt uses ENCRYPTED_MESSAGE_CHARSET = "US-ASCII")
	if e.isBase64 {
		return encoding.EncodeBase64(encrypted), nil
	}
	return encoding.EncodeHex(encrypted), nil
}

// Decrypt decrypts a Base64/Hex encoded string and returns the original message.
func (e *StringEncryptor) Decrypt(encryptedMessage string) (string, error) {
	if encryptedMessage == "" {
		return "", nil
	}

	// Decode from Base64 or Hex
	var encryptedBytes []byte
	var err error
	if e.isBase64 {
		encryptedBytes, err = encoding.DecodeBase64(encryptedMessage)
	} else {
		encryptedBytes, err = encoding.DecodeHex(encryptedMessage)
	}
	if err != nil {
		return "", fmt.Errorf("pbe: failed to decode encrypted message: %w", err)
	}

	// Decrypt
	decrypted, err := e.byteEncryptor.Decrypt(encryptedBytes)
	if err != nil {
		return "", fmt.Errorf("pbe: decryption failed: %w", err)
	}

	// UTF-8 bytes → String
	return string(decrypted), nil
}

// SetPassword changes the password after initialization.
// In jasypt, this is not allowed after initialization, but we allow it for simplicity.
func (e *StringEncryptor) SetPassword(password string) {
	e.byteEncryptor.config.Password = password
}

// Config returns the current configuration.
func (e *StringEncryptor) Config() *Config {
	return e.byteEncryptor.config
}
