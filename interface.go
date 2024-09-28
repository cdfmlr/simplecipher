// Package simplecipher wraps the standard library's crypto/cipher package.
//
// It provides a simple interface to encrypt and decrypt strings or
// io.Reader/io.Writer streams using AES encryption.
package simplecipher

import (
	"errors"
	"io"
)

// Cipher is an interface for encryption and decryption of strings.
//
// Cipher implementations should recover from underlying panics
// and return them as errors.
//
// Cipher encodes the ciphertext with [DefaultStringCodec] when Encrypting
// and decodes the ciphertext from a [DefaultStringCodec] string when Decrypting.
type Cipher interface {
	// Encrypt the given plaintext and return the ciphertext as a [DefaultStringCodec] encoded string.
	Encrypt(plainText string) (cipherText string, err error)
	// Decrypt the given ciphertext ([DefaultStringCodec] encoded) and return the plaintext.
	Decrypt(cipherText string) (plainText string, err error)
}

// Stream is an interface for encryption and decryption of io.Reader and io.Writer.
//
// Notice that, unlike [Cipher], Stream does not encode the ciphertext.
// The cipherText output of Encrypt and the cipherText input of Decrypt
// are not encoded in any way (or in [NopCodec]), they are just raw bytes.
type Stream interface {
	// EncryptStream encrypts the given plaintext from the reader
	// and write the ciphertext to the given writer without encoding.
	EncryptStream(plainText io.Reader, cipherText io.Writer) error
	// DecryptStream decrypts the given ciphertext (not encoded)
	// and write the plaintext to the given writer.
	DecryptStream(cipherText io.Reader, plainText io.Writer) error
}

// Errors
var (
	ErrPlaintextBlockSize  = errors.New("plaintext is not a multiple of the block size")
	ErrCipherTextTooShort  = errors.New("ciphertext too short")
	ErrCipherTextBlockSize = errors.New("ciphertext is not a multiple of the block size")
	ErrPanic               = errors.New("recovered from panic")
	ErrCopy                = errors.New("copy error")
	ErrNewAesCipher        = errors.New("aes.NewCipher error")
)
