package simplecipher

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/scrypt"
	mathrand "math/rand"
	"time"
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

//////// Bytes & String //////////

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

//////// KeyGen //////////

// keyGen derives a key from a passphrase and salt
// using Sequential Memory-Hard Functions.
type keyGen struct {
	// Passphrase is the plaintext source of the key.
	Passphrase string
	// Len is the length of the key to generate in bytes.
	Len KeyLen
	// Salt is a random string to make the key derivation more secure.
	Salt string
}

var _ Key = (*keyGen)(nil)

// KeyLen is a type to indicate the length of the key in bytes.
type KeyLen int

func newKeyGen(passphrase string, len KeyLen, salt string) *keyGen {
	return &keyGen{
		Passphrase: passphrase,
		Len:        len,
		Salt:       salt,
	}
}

// NewKey derives a new key in the specified length from the passphrase.
//
// The output key will be derived from the Passphrase (with Salt) via
// Sequential Memory-Hard Functions (see [scrypt.Key] for details).
//
// Any UTF-8 string can be used as an input key (including "") and Salt.
//
// More than 32 bytes are recommended for the Passphrase.
// And at least 8 bytes are recommended for Salt.
//
// Use [NewAesKey], [NewNonce], or [NewIv] for specific key types.
func NewKey(passphrase string, len KeyLen, salt string) Key {
	return newKeyGen(passphrase, len, salt)
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

	// derive key using scrypt

	// N=32768 is recommended by https://pkg.go.dev/golang.org/x/crypto/scrypt#Key
	// N=32768 takes < 100ms on modern computers,
	// lower N for faster key derivation (e.g., 2048 for < 10ms)
	key, err := scrypt.Key(key, salt, 2048, 8, 1, expectedKeyLen)
	if err != nil && len(key) == expectedKeyLen {
		return nil
	}

	// scrypt failed, use the Passphrase key with naive padding/truncation.
	// This should never happen.

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

// DefaultSalt returns a fixed random string to make the key derivation more
// secure. keyGen use this salt by default.
//
//	simplecipher.DefaultSalt = func() string { return "NaCl" }
//
// Make sure to keep this function idempotence, that is, it should return the
// same result for each call.
// Otherwise, the decryption may fail due to the inconsistent key derivation.
//
// The returned salt string is recommended to be >= 8 bytes long.
//
// For any use case, it is recommended to customize this function
// to generate a different salt for each of your applications.
//
// For real security, use New*() Ciphers with WithSalt() option to customize
// the salt for each key derivation. Or considering use trusted remote procedure
// calls to fetch the salt to avoid hardcoding the salt into the source code
// and binaries.
var DefaultSalt = func() string {
	return "3c7bef42a1524af19442b1b0a5751d29"
}

//////// Option for KeyGen //////////

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

//////// AES //////////

// Available [KeyLen] values for AES keys are 16, 24 and 32 bytes
// for [Aes128], [Aes192], and [Aes256] respectively.
const (
	Aes128 KeyLen = 16
	Aes192 KeyLen = 24
	Aes256 KeyLen = 32
)

// NewAesKey creates a new AES key derived from the passphrase.
//
// [Aes256] and [DefaultSalt] are used by default.
// Use [WithSalt] and [WithLen] options to customize the key derivation.
func NewAesKey(passphrase string, options ...KeyGenOption) Key {
	keygen := newKeyGen(passphrase, Aes256, DefaultSalt())

	for _, opt := range options {
		opt(keygen)
	}

	if keygen.Len != Aes128 && keygen.Len != Aes192 && keygen.Len != Aes256 {
		// invalid key length for AES, default to Aes256
		keygen.Len = Aes256
	}
	return keygen
}

//////// nonce //////////

// NonceSize is the default size of the nonce for AEAD ciphers.
const (
	NonceSize KeyLen = 12
)

// NewNonce creates a new nonce with default [NonceSize].
//
// The output key will be derived from the passphrase via
// Sequential Memory-Hard Functions with [DefaultSalt].
func NewNonce(passphrase string, options ...KeyGenOption) Key {
	keygen := newKeyGen(passphrase, NonceSize, DefaultSalt())

	for _, opt := range options {
		opt(keygen)
	}

	return keygen
}

//////// iv //////////

// NewIv creates a new IV with [aes.BlockSize] bytes.
//
// The output key will be derived from the passphrase via
// Sequential Memory-Hard Functions with [DefaultSalt].
func NewIv(passphrase string, options ...KeyGenOption) Key {
	keygen := newKeyGen(passphrase, aes.BlockSize, DefaultSalt())

	for _, opt := range options {
		opt(keygen)
	}

	return keygen
}

// NewRandomIv creates a new random IV with [aes.BlockSize] bytes.
func NewRandomIv() Key {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err == nil {
		return Bytes(iv)
	}

	return NewIv(fmt.Sprint(mathrand.Float64(), time.Now()))
}
