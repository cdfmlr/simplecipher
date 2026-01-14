// Package kdf defines the KeyDerivation interface for key derivation functions.
// It also provides common KDF implementations including PBKDF2, scrypt, and Argon2id.
package kdf

import (
	"errors"
)

// KeyDerivation is a key derivation function (KDF) interface.
//
// Prefer:
//   - generic key derivation: Argon2id > scrypt > PBKDF2.
//   - for machine secrets (fast key splitting/refining): use HKDF.
//
// Edge cases:
//   - password and salt can be any legal []byte value,
//     including empty byte slice, nil, and arbitrary length.
//   - keyLen can be zero: resulting in an empty key and nil error ([]byte{}, nil).
//   - keyLen cannot be negative: resulting in a nil key and an error (nil, ErrNegKeyLen).
//   - keyLen is limited to maximum of 1<<20 bytes for PBKDF2 and 1<<11 bytes
//     for HKDF, for performance and entropy reasons respectively.
//     Argon2id and scrypt are limited to 1<<31 bytes.
//
// KeyDerivation is for internal use in simplecipher only.
// So it is NOT simplified to accept string args like the outer Block/Stream
// interfaces do. This is by design.
type KeyDerivation interface {
	// Derive derives a key from the given password and salt.
	Derive(password, salt []byte, keyLen int) ([]byte, error)
}

// ErrNegKeyLen indicates that the provided key length (keyLen) is negative,
// which is invalid for key derivation functions. In such cases,
// a nil byte slice and ErrNegKeyLen should be returned by the Derive method.
var (
	ErrNegKeyLen = errors.New("invalid key length (negative)")
	ErrPanic     = errors.New("recovered from panic")
	ErrKdfConfig = errors.New("invalid KDF configuration")
)
