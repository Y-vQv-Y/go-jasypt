// Package util provides common utilities for the jasypt Go implementation.
package util

import (
	"golang.org/x/text/unicode/norm"
)

// NormalizeToNfc applies Unicode NFC normalization to a string.
// jasypt applies NFC normalization to the password before key derivation
// to ensure consistent behavior across different Unicode representations.
// e.g., "café" with composed é (U+00E9) and decomposed é (U+0065 U+0301)
// will produce the same normalized form.
func NormalizeToNfc(s string) string {
	return norm.NFC.String(s)
}
