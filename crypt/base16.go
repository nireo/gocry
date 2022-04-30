package crypt

import (
	b64 "encoding/base64"
)

// The idea behind using base64 decoding is because we want to hide strings, such as the
// ransom requirements behind some encryption, such that signature based scanners, won't
// detect the software so easily.

// Ignore errors as it makes the code cleaner and this operation will most likely not fail.
func DecodeBase16String(toDecode string) string {
	decoded, _ := b64.StdEncoding.DecodeString(toDecode)
	return string(decoded)
}
