package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

func Make() {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, _ = rsaKey, ecKey
}