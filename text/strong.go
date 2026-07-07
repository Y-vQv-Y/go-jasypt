package text

import (
	"github.com/Y-vQv-Y/go-jasypt/pbe"
)

// StrongTextEncryptor is a convenience encryptor pre-configured with PBEWithMD5AndTripleDES.
// This mirrors org.jasypt.util.text.StrongTextEncryptor.
//
// Note: Using TripleDES requires the full 192-bit key.
// This algorithm may need JCE Unlimited Strength Policy Files in Java.
//
// Usage:
//
//	enc := text.NewStrongTextEncryptor()
//	enc.SetPassword("mySecret")
//	encrypted, _ := enc.Encrypt("sensitive data")
type StrongTextEncryptor struct {
	encryptor *pbe.StringEncryptor
}

// NewStrongTextEncryptor creates a new StrongTextEncryptor with PBEWithMD5AndTripleDES.
func NewStrongTextEncryptor() *StrongTextEncryptor {
	config := pbe.DefaultConfig()
	config.Algorithm = "PBEWithMD5AndTripleDES"
	enc, _ := pbe.NewStringEncryptor(config)
	return &StrongTextEncryptor{encryptor: enc}
}

// SetPassword sets the encryption password.
func (e *StrongTextEncryptor) SetPassword(password string) {
	e.encryptor.SetPassword(password)
}

// Encrypt encrypts a string message.
func (e *StrongTextEncryptor) Encrypt(message string) (string, error) {
	return e.encryptor.Encrypt(message)
}

// Decrypt decrypts a string message.
func (e *StrongTextEncryptor) Decrypt(encryptedMessage string) (string, error) {
	return e.encryptor.Decrypt(encryptedMessage)
}
