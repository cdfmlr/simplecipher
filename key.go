package simplecipher

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"time"

	"github.com/cdfmlr/simplecipher/v2/kdf"
)

// This file provides a helper interface and struct to create AES keys.
// From arbitrary strings, to fixed-length byte slices.

// Key is an interface for AES cipher keys, ivs, and nonces.
//
// To keep things simple, basically everything you need to
// encrypt/decrypt with AES, except the plaintext/ciphertext,
// are treated as keys in this package.
//
// Notice different use cases of keys require different lengths.
// Use [NewAesKey], [NewNonce], or [NewIv] to create keys
// matching the requirements if you are not sure.
type Key interface {
	// Bytes return a byte slice of the key.
	Bytes() []byte
}

// ////// Bytes & String //////////

// bytesKey is a simple type to convert a byte slice to a [Key].
type bytesKey []byte

var _ Key = (*bytesKey)(nil)

func (k bytesKey) Bytes() []byte {
	return k
}

// Bytes is a helper function to convert a byte slice to a [Key].
func Bytes(b []byte) Key {
	return bytesKey(b)
}

// stringKey is a simple type to convert a string to a [Key].
type stringKey string

func (k stringKey) Bytes() []byte {
	return []byte(k)
}

// String is a helper function to convert a string to a [Key].
func String(s string) Key {
	return stringKey(s)
}

// ////// KeyGen //////////

// keyGen derives a key from a passphrase and salt
// using Sequential Memory-Hard Functions.
type keyGen struct {
	// Passphrase is the plaintext source of the key.
	Passphrase string
	// Len is the length of the key to generate in bytes.
	Len KeyLen
	// Salt is a random string to make the key derivation more secure.
	Salt string
	// KeyDerivation is the KDF function to use for key derivation.
	KeyDerivation kdf.KeyDerivation
}

var _ Key = (*keyGen)(nil)

// KeyLen is a type to indicate the length of the key in bytes.
type KeyLen = int

func newKeyGen(passphrase string, len KeyLen, salt string, keyDerivation kdf.KeyDerivation) *keyGen {
	return &keyGen{
		Passphrase:    passphrase,
		Len:           len,
		Salt:          salt,
		KeyDerivation: keyDerivation,
	}
}

// Bytes return the key as a byte slice.
//
// It will derive bytes in correct length (Len) from the input (Passphrase) key.
//
// Len <= 0 will return an empty byte slice ([]byte{}).
func (k keyGen) Bytes() []byte {
	key := []byte(k.Passphrase)
	salt := []byte(k.Salt)
	expectedKeyLen := int(k.Len)

	if expectedKeyLen < 0 {
		expectedKeyLen = 0
	}

	// derive key using the configured KeyDerivation function
	var err error
	if k.KeyDerivation != nil {
		key, err = k.KeyDerivation.Derive(key, salt, expectedKeyLen)
		if err == nil && len(key) == expectedKeyLen {
			return key
		}
	}

	// KDF failed or not configured, use the Passphrase key with naive padding/truncation.
	// This should never happen when KeyDerivation is properly configured.

	keyLength := len(key)
	if keyLength < expectedKeyLen {
		// pad with padding
		for i := keyLength; i < expectedKeyLen; i++ {
			key = append(key, byte(i%256))
		}
	} else if keyLength > expectedKeyLen {
		// truncate
		key = key[:expectedKeyLen]
	}

	return key
}

// ////// Option for KeyGen //////////

// KeyGenOption is a functional option to customize the KeyGen struct.
type KeyGenOption func(gen *keyGen)

// WithPassphrase sets the passphrase for the key derivation.
// The passphrase can be any UTF-8 string.
// The length of the passphrase is recommended to be >= 32 bytes for security
// and < 72 bytes for performance.
func WithPassphrase(passphrase string) KeyGenOption {
	return func(gen *keyGen) {
		gen.Passphrase = passphrase
	}
}

// WithSalt sets the salt for the key derivation.
// The salt should be a random string >= 8 bytes long
// to make the key derivation more secure.
func WithSalt(salt string) KeyGenOption {
	return func(gen *keyGen) {
		gen.Salt = salt
	}
}

// WithLen sets the key length for the AES key.
// Available key lengths are [Aes128], [Aes192], and [Aes256].
//
// If an invalid key length is provided, it will default to [Aes256].
func WithLen(keyLen KeyLen) KeyGenOption {
	if keyLen != Aes128 && keyLen != Aes192 && keyLen != Aes256 {
		// invalid key length for AES, default to Aes256
		keyLen = Aes256
	}
	return func(gen *keyGen) {
		gen.Len = keyLen
	}
}

// ////// AES //////////

// Available [KeyLen] values for AES keys are 16, 24 and 32 bytes
// for [Aes128], [Aes192], and [Aes256] respectively.
const (
	Aes128 KeyLen = 16
	Aes192 KeyLen = 24
	Aes256 KeyLen = 32
)

func newAesKey(passphrase string, options []KeyGenOption, p *config) Key {
	keygen := newKeyGen(passphrase, Aes256, p.SaltFunc(), p.KeyDerivation)

	for _, opt := range options {
		opt(keygen)
	}

	if keygen.Len != Aes128 && keygen.Len != Aes192 && keygen.Len != Aes256 {
		// invalid key length for AES, default to Aes256
		keygen.Len = Aes256
	}
	return keygen
}

// ////// nonce //////////

// NonceSize is the default size of the nonce for AEAD ciphers.
const (
	NonceSize KeyLen = 12
	// TagSize   KeyLen = 16
)

func newNonce(passphrase string, options []KeyGenOption, p *config) Key {
	keygen := newKeyGen(passphrase, NonceSize, p.SaltFunc(), p.KeyDerivation)

	for _, opt := range options {
		opt(keygen)
	}

	return keygen
}

func newRandomNonce(p *config) Key {
	iv := make([]byte, NonceSize)
	_, err := rand.Read(iv)
	if err == nil {
		return Bytes(iv)
	}

	// Fallback to deterministic generation if crypto/rand fails
	return p.NewIv(fmt.Sprint(mathrand.Float64(), time.Now()))
}

// ////// iv //////////

func newIv(passphrase string, options []KeyGenOption, p *config) Key {
	keygen := newKeyGen(passphrase, aes.BlockSize, p.SaltFunc(), p.KeyDerivation)

	for _, opt := range options {
		opt(keygen)
	}

	return keygen
}

func newRandomIv(p *config) Key {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err == nil {
		return Bytes(iv)
	}

	// Fallback to deterministic generation if crypto/rand fails
	return p.NewIv(fmt.Sprint(mathrand.Float64(), time.Now()))
}
