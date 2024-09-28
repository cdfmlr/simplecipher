package simplecipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

// This package implements  AES stream cipher modes.
//
// Available modes are:
//
//   - CFB (Cipher Feedback)
//   - OFB (Output Feedback)
//   - CTR (Counter)
//
// See also:
//  - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Confidentiality_only_modes
//  - https://pkg.go.dev/crypto/cipher@go1.23.1#Stream

// steam is a wrapper around the AES-Stream cipher mode implementation
// for the Stream interface.
//
// Given different cipherStream, steam can become CFB, OFB, or CTR.
type steam struct {
	key          Key
	iv           Key
	cipherStream cipherStreamBuilder
}

var _ Stream = (*steam)(nil)

// EncryptStream encrypts the given plaintext using CFB.
// The ciphertext is written to the given writer without encoding.
func (s *steam) EncryptStream(plainText io.Reader, cipherText io.Writer) (err error) {
	defer recoverPanic(&err)

	key := s.key.Bytes()
	iv := s.iv.Bytes()

	stream, err := s.cipherStream(key, iv, encrypt)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNewAesCipher, err)
	}

	_, err = cipherText.Write(iv)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCopy, err)
	}

	writer := &cipher.StreamWriter{S: stream, W: cipherText}
	if _, err := io.Copy(writer, plainText); err != nil {
		return fmt.Errorf("%w: %w", ErrCopy, err)
	}

	return nil
}

// DecryptStream decrypts the given ciphertext using CFB.
// The ciphertext read from the given reader should not be encoded.
func (s *steam) DecryptStream(cipherText io.Reader, plainText io.Writer) (err error) {
	defer recoverPanic(&err)

	key := s.key.Bytes()

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(cipherText, iv); err != nil {
		return fmt.Errorf("%w: %w", ErrCopy, err)
	}

	stream, err := s.cipherStream(key, iv, decrypt)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNewAesCipher, err)
	}

	reader := &cipher.StreamReader{S: stream, R: cipherText}
	if _, err := io.Copy(plainText, reader); err != nil {
		return fmt.Errorf("%w: %w", ErrCopy, err)
	}

	return nil
}

//////// CFB, OFB, CTR ////////

// cipherStreamBuilder is a function that creates a new [cipher.Stream].
// Available implementations are cfbStreamBuilder, ofbStreamBuilder, and ctrStreamBuilder.
type cipherStreamBuilder func(key []byte, iv []byte, encryptOrDecrypt encryptOrDecrypt) (cipher.Stream, error)

func cfbStreamBuilder(key []byte, iv []byte, encryptOrDecrypt encryptOrDecrypt) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	switch encryptOrDecrypt {
	case encrypt:
		return cipher.NewCFBEncrypter(block, iv), nil
	case decrypt:
		return cipher.NewCFBDecrypter(block, iv), nil
	default:
		return nil, fmt.Errorf("invalid encryptOrDecrypt: %v", encryptOrDecrypt)
	}
}

func ofbStreamBuilder(key []byte, iv []byte, _ encryptOrDecrypt) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewOFB(block, iv), nil
}

func ctrStreamBuilder(key []byte, iv []byte, _ encryptOrDecrypt) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

// encryptOrDecrypt is an enum to indicate the operation of the cipher.
// For CFB only, which uses different [cipher.Stream] implementations for encryption and decryption.
type encryptOrDecrypt int

const (
	encrypt encryptOrDecrypt = iota
	decrypt
)

//////// Exported Constructors ////////

// NewCFBStream creates a new CFB stream cipher with the given key and iv.
//
// The iv will be used as the initial value for the CFB mode.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
func NewCFBStream(key, iv Key) Stream {
	return &steam{key: key, iv: iv, cipherStream: cfbStreamBuilder}
}

// SimpleCFBStream creates a new AES-256-CFB stream cipher from the given key and iv.
//
// An [Aes256] key for encryption/decryption will be derived from the
// arbitrary keyPassphrase string via scrypt.
//
// The iv will be a random value.
func SimpleCFBStream(keyPassphrase string) Stream {
	return NewCFBStream(NewAesKey(keyPassphrase), NewRandomIv())
}

// NewOFBStream creates a new OFB stream cipher with the given key and iv.
//
// The iv will be used as the initial value for the OFB mode.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
func NewOFBStream(key, iv Key) Stream {
	return &steam{key: key, iv: iv, cipherStream: ofbStreamBuilder}
}

// SimpleOFBStream creates a new AES-256-OFB stream cipher from the given key and iv.
//
// An [Aes256] key for encryption/decryption will be derived from the
// arbitrary keyPassphrase string via scrypt.
//
// The iv will be a random value.
func SimpleOFBStream(keyPassphrase string) Stream {
	return NewOFBStream(NewAesKey(keyPassphrase), NewRandomIv())
}

// NewCTRStream creates a new CTR stream cipher with the given key and iv.
//
// The iv will be used as the initial value for the CTR mode.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
func NewCTRStream(key, iv Key) Stream {
	return &steam{key: key, iv: iv, cipherStream: ctrStreamBuilder}
}

// SimpleCTRStream creates a new AES-256-CTR stream cipher from the given key and iv.
//
// An [Aes256] key for encryption/decryption will be derived from the
// arbitrary keyPassphrase string via scrypt.
//
// The iv will be a random value.
func SimpleCTRStream(keyPassphrase string) Stream {
	return NewCTRStream(NewAesKey(keyPassphrase), NewRandomIv())
}
