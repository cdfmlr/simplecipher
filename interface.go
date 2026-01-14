// Package simplecipher wraps the standard library's crypto/cipher package.
//
// It provides a simple interface to encrypt and decrypt strings or
// io.Reader/io.Writer streams using AES and choices of cipher modes.
package simplecipher

import (
	"errors"
	"io"

	"github.com/cdfmlr/simplecipher/v2/codec"
	"github.com/cdfmlr/simplecipher/v2/dontpanic"
	"github.com/cdfmlr/simplecipher/v2/kdf"
)

// Block is an interface for encryption and decryption of strings.
//
// Block implementations should recover from underlying panics
// and return them as errors.
//
// Block encodes the ciphertext with [Provider.StringCodec] when Encrypting
// and decodes the ciphertext from a [Provider.StringCodec] string when Decrypting.
type Block interface {
	// Encrypt the given plaintext and return the ciphertext as a [Provider.StringCodec] encoded string.
	Encrypt(plainText string) (cipherText string, err error)
	// Decrypt the given ciphertext ([Provider.StringCodec] encoded) and return the plaintext.
	Decrypt(cipherText string) (plainText string, err error)
}

// Stream is an interface for encryption and decryption of io.Reader and io.Writer.
//
// Notice that, unlike [Block], Stream does not encode the ciphertext.
// The cipherText output of Encrypt and the cipherText input of Decrypt
// are not encoded in any way (or in [codec.Nop]), they are just raw bytes.
type Stream interface {
	// EncryptStream encrypts the given plaintext from the reader
	// and write the ciphertext to the given writer without encoding.
	EncryptStream(plainText io.Reader, cipherText io.Writer) error
	// DecryptStream decrypts the given ciphertext (not encoded)
	// and write the plaintext to the given writer.
	DecryptStream(cipherText io.Reader, plainText io.Writer) error
}

// KeyDerivation is a key derivation function (KDF) interface.
// See [kdf.KeyDerivation] for details.
type KeyDerivation = kdf.KeyDerivation

// StringCodec is an interface that provides encoding and decoding functions
// for ciphertexts. See [codec.StringCodec] for details.
type StringCodec = codec.StringCodec

// SaltFunc is a function type that returns a salt string.
//
// A SaltFunc should be deterministic, i.e. it MUST return the same salt
// string whenever it is called.
// (Otherwise, decryption will fail,
// unless you design the func/process very trickily.)
//
// Typically, a SaltFunc is a simple wrapper around a constant string:
//
//	func() string { return "my-fixed-salt" }
type SaltFunc = func() string

// Errors
var (
	ErrPlaintextBlockSize  = errors.New("plaintext is not a multiple of the block size")
	ErrCipherTextTooShort  = errors.New("ciphertext too short")
	ErrCipherTextBlockSize = errors.New("ciphertext is not a multiple of the block size")
	ErrCopy                = errors.New("copy error")
	ErrNewAesCipher        = errors.New("aes.NewCipher error")
	ErrPanic               = dontpanic.ErrPanic
)
