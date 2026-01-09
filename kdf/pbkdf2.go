package kdf

import (
	"crypto/sha1"
	"crypto/sha256"
	"hash"

	cryptoPbkdf2 "golang.org/x/crypto/pbkdf2"
)

// pbkdf2 derives a key based on the method described as PBKDF2 with the HMAC
// variant using the supplied hash function.
type pbkdf2 struct {
	Iter int
	Hash func() hash.Hash
}

// NewPbkdf2 creates a PBKDF2 key derivation function.
//
// pbkdf2 derives a key based on the method described as PBKDF2 with the HMAC
// variant using the supplied hash function.
//
// Using a higher iteration count will increase the cost of an exhaustive
// search but will also make derivation proportionally slower.
func NewPbkdf2(iter int, hashFunc func() hash.Hash) KeyDerivation {
	return &pbkdf2{
		Iter: iter,
		Hash: hashFunc,
	}
}

var _ KeyDerivation = (*pbkdf2)(nil)

// Derive a key from the given password and salt using PBKDF2.
//
// Remember to get a good random salt. At least 8 bytes is recommended by the
// RFC.
func (p *pbkdf2) Derive(password, salt []byte, keyLen int) (key []byte, err error) {
	defer recoverFromPanic(&err)

	key = cryptoPbkdf2.Key(password, salt, p.Iter, keyLen, p.Hash)
	return key, nil
}

// profiles

// CheapPbkdf2 uses 10,000 SHA1 iterations for low memory usage and fast derivation. Commonly take <=1ms on modern (2025) hardware.
//
// It is NOT recommended for new applications.
func CheapPbkdf2() KeyDerivation {
	return &pbkdf2{
		Iter: 10000,
		Hash: sha1.New,
	}
}

// RecommendedPbkdf2 uses 100,000 SHA256 iterations as of 2024 recommendations.
//
// Commonly take around 10ms on modern (2025) hardware.
func RecommendedPbkdf2() KeyDerivation {
	return &pbkdf2{
		Iter: 100000,
		Hash: sha256.New,
	}
}

// StrongPbkdf2 uses 600,000 SHA256 iterations for stronger security as
// of OWASP recommendations.
//
// Commonly take around 50ms on modern (2025) hardware.
func StrongPbkdf2() KeyDerivation {
	return &pbkdf2{
		Iter: 600000,
		Hash: sha256.New,
	}
}
