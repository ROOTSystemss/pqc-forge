package keys

import (
	"crypto/sha256"
	"encoding/hex"
)

// rsa.GenerateKey is mentioned in this comment only.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}