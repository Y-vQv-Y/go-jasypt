// Package text provides convenient, pre-configured text encryptors
// for common PBE encryption use cases.
package text

import (
	"github.com/Y-vQv-Y/go-jasypt/pbe"
)

// BasicTextEncryptor is a convenience encryptor pre-configured with PBEWithMD5AndDES.
// This mirrors org.jasypt.util.text.BasicTextEncryptor.
//
// Usage:
//
//	enc := text.NewBasicTextEncryptor()
//	enc.SetPassword("mySecret")
//	encrypted, _ := enc.Encrypt("hello")
//	decrypted, _ := enc.Decrypt(encrypted)
type BasicTextEncryptor struct {
	encryptor *pbe.StringEncryptor
}

// NewBasicTextEncryptor creates a new BasicTextEncryptor with PBEWithMD5AndDES.
func NewBasicTextEncryptor() *BasicTextEncryptor {
	config := pbe.DefaultConfig()
	config.Algorithm = "PBEWithMD5AndDES"
	enc, _ := pbe.NewStringEncryptor(config)
	return &BasicTextEncryptor{encryptor: enc}
}

// SetPassword sets the encryption password.
func (e *BasicTextEncryptor) SetPassword(password string) {
	e.encryptor.SetPassword(password)
}

// Encrypt encrypts a string message.
func (e *BasicTextEncryptor) Encrypt(message string) (string, error) {
	return e.encryptor.Encrypt(message)
}

// Decrypt decrypts a string message.
func (e *BasicTextEncryptor) Decrypt(encryptedMessage string) (string, error) {
	return e.encryptor.Decrypt(encryptedMessage)
}
