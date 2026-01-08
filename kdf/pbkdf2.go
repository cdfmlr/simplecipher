package kdf

import (
	"crypto/sha1"
	"crypto/sha256"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// Pbkdf2 derives a key based on the method described as PBKDF2 with the HMAC
// variant using the supplied hash function.
//
// Using a higher iteration count will increase the cost of an exhaustive
// search but will also make derivation proportionally slower.
type Pbkdf2 struct {
	Iter int
	Hash func() hash.Hash
}

var _ KeyDerivation = (*Pbkdf2)(nil)

// Derive a key from the given password and salt using PBKDF2.
//
// Remember to get a good random salt. At least 8 bytes is recommended by the
// RFC.
func (p *Pbkdf2) Derive(password, salt []byte, keyLen int) (key []byte, err error) {
	defer recoverFromPanic(&err)

	key = pbkdf2.Key(password, salt, p.Iter, keyLen, p.Hash)
	return key, nil
}

// profiles

// cheapPbkdf2 uses 10,000 SHA1 iterations for low memory usage and fast derivation.
func cheapPbkdf2() *Pbkdf2 {
	return &Pbkdf2{
		Iter: 10000,
		Hash: sha1.New,
	}
}

// recommendedPbkdf2 uses 100,000 SHA256 iterations as of 2024 recommendations.
func recommendedPbkdf2() *Pbkdf2 {
	return &Pbkdf2{
		Iter: 100000,
		Hash: sha256.New,
	}
}

// strongPbkdf2 uses 600,000 SHA256 iterations for stronger security as
// of OWASP recommendations.
func strongPbkdf2() *Pbkdf2 {
	return &Pbkdf2{
		Iter: 600000,
		Hash: sha256.New,
	}
}
