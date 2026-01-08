package kdf

import (
	"crypto/sha256"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Hkdf is a cryptographic key derivation function with the goal of
// expanding limited input keying material into one or more cryptographically
// strong secret keys. Defined in RFC 5869.
//
// Hkdf is NOT for **human-created password** (low entropy).
// If you use HKDF on a human password like "P@ssword123",
// an attacker can crack it instantly because HKDF is designed to be fast.
type Hkdf struct {
	Hash func() hash.Hash
	// Info is optional context information for the derived key.
	Info []byte
	// Iter determines the number of keys to derive (read and discard) before
	// the returned one.
	Iter int
}

var _ KeyDerivation = (*Hkdf)(nil)

// Derive a key from the given password and salt using HKDF.
// Remember to get a good random salt.
func (h *Hkdf) Derive(password, salt []byte, keyLen int) (key []byte, err error) {
	defer recoverFromPanic(&err)

	hkdfReader := hkdf.New(h.Hash, password, salt, h.Info)

	key = make([]byte, keyLen)

	// Read and discard keys
	for i := 0; i < h.Iter; i++ {
		if _, err = io.ReadFull(hkdfReader, key); err != nil {
			return nil, err
		}
	}
	// use the last derived key
	_, err = io.ReadFull(hkdfReader, key)
	return key, err
}

// profiles

// we don't recommend any HKDF profile, just for completeness.
func cheapHkdf() *Hkdf {
	return &Hkdf{
		Hash: sha256.New,
		Info: nil,
		Iter: 0,
	}
}

// we don't recommend any HKDF profile, just for completeness.
func recommendedHkdf() *Hkdf {
	return &Hkdf{
		Hash: sha256.New,
		Info: []byte("MGUwOTRj"), // info is actually non-secret context info
		Iter: 1,
	}
}

// we don't recommend any HKDF profile, just for completeness.
func strongHkdf() *Hkdf {
	return &Hkdf{
		Hash: sha256.New,
		Info: []byte("ZTQwODc2ZWYtMmQy"), // info is actually non-secret context info
		Iter: 2,
	}
}
