// Package encoding provides Base64 and Hexadecimal encoding/decoding utilities
// compatible with jasypt's output formats.
package encoding

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// EncodeBase64 encodes bytes to a standard Base64 string (no line breaks),
// compatible with jasypt's Apache Commons Codec 1.3 RFC 2045 Base64.
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes a standard Base64 string to bytes.
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// EncodeHex encodes bytes to an uppercase hexadecimal string,
// compatible with jasypt's CommonUtils.toHexadecimal().
func EncodeHex(data []byte) string {
	return fmt.Sprintf("%X", data)
}

// DecodeHex decodes a hexadecimal string to bytes.
func DecodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
