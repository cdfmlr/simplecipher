package kdf

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"

	cryptoHkdf "golang.org/x/crypto/hkdf"
)

// hkdf is a cryptographic key derivation function with the goal of
// expanding limited input keying material into one or more cryptographically
// strong secret keys. Defined in RFC 5869.
//
// hkdf is NOT for **human-created password** (low entropy).
// If you use HKDF on a human password like "P@ssword123",
// an attacker can crack it instantly because HKDF is designed to be fast.
type hkdf struct {
	Hash func() hash.Hash
	// Info is optional context information for the derived key.
	Info []byte
	// Iter determines the number of keys to derive (read and discard) before
	// the returned one.
	Iter int
}

func NewHkdf(hashFunc func() hash.Hash, info []byte, iter int) KeyDerivation {
	return &hkdf{
		Hash: hashFunc,
		Info: info,
		Iter: iter,
	}
}

var _ KeyDerivation = (*hkdf)(nil)

func (h *hkdf) check() error {
	if h.Iter < 0 {
		return fmt.Errorf("%w: hkdf iter parameter must be non-negative", ErrKdfConfig)
	}
	if h.Hash == nil {
		return fmt.Errorf("%w: hkdf hash function must be non-nil", ErrKdfConfig)
	}
	return nil
}

// Derive a key from the given password and salt using HKDF.
// Remember to get a good random salt.
//
// The keyLen is limited to maximum of 1<<20 (1M) bytes as HKDF has entropy limit.
func (h *hkdf) Derive(password, salt []byte, keyLen int) (key []byte, err error) {
	defer recoverFromPanic(&err)

	if err := h.check(); err != nil {
		return nil, err
	}

	if keyLen == 0 {
		return []byte{}, nil
	}
	if keyLen < 0 {
		return nil, ErrNegKeyLen
	}
	if keyLen > 1<<11 {
		return nil, fmt.Errorf("%w: key length too large: hkdf entropy limit", ErrKdfConfig)
	}

	hkdfReader := cryptoHkdf.New(h.Hash, password, salt, h.Info)

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

// CheapHkdf uses SHA256 with no info and no extra iterations for HKDF.
func CheapHkdf() KeyDerivation {
	return &hkdf{
		Hash: sha256.New,
		Info: nil,
		Iter: 0,
	}
}

// RecommendedHkdf uses SHA256 with hardcoded info "MGUwOTRj" (random generated
// by developer) and 1 extra iteration for HKDF.
func RecommendedHkdf() KeyDerivation {
	return &hkdf{
		Hash: sha256.New,
		Info: []byte("MGUwOTRj"), // info is actually non-secret context info
		Iter: 1,
	}
}

// StrongHkdf uses SHA256 with hardcoded info "ZTQwODc2ZWYtMmQy" (random generated
// by developer) and 2 extra iterations for HKDF.
func StrongHkdf() KeyDerivation {
	return &hkdf{
		Hash: sha256.New,
		Info: []byte("ZTQwODc2ZWYtMmQy"), // info is actually non-secret context info
		Iter: 2,
	}
}
