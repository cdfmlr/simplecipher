package simplecipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"

	"github.com/cdfmlr/simplecipher/v2/dontpanic"
)

// This package implements  AES stream cipher modes.
//
// Available modes are:
//
//   - CFB (Block Feedback)
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

// newSteam is an internal constructor for steam cipher.
func newSteam(key, iv Key, cipherStream cipherStreamBuilder) Stream {
	return &steam{key: key, iv: iv, cipherStream: cipherStream}
}

// EncryptStream encrypts the given plaintext using CFB.
// The ciphertext is written to the given writer without encoding.
func (s *steam) EncryptStream(plainText io.Reader, cipherText io.Writer) (err error) {
	defer dontpanic.RecoverTo(&err)

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
	defer dontpanic.RecoverTo(&err)

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

// ////// CFB, OFB, CTR ////////

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

// ////// Exported Constructors ////////

// NewCFBStream creates a new CFB stream cipher with the given key and iv using the DefaultProvider.
//
// The iv will be used as the initial value for the CFB mode.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
//
// Use [SimpleCFBStream] if you are not familiar with these.
// See also: [cipher.NewCFBDecrypter], [cipher.NewCFBEncrypter] for low-level usage.
func NewCFBStream(key, iv Key) Stream {
	return DefaultProvider.NewCFBStream(key, iv)
}

// SimpleCFBStream creates a new AES-256-CFB stream cipher from the given key and iv using the DefaultProvider.
//
// An [Aes256] key for encryption/decryption will be derived from the
// arbitrary keyPassphrase string via scrypt.
//
// The iv will be a random value.
//
// See also: [NewCFBStream] for more control.
func SimpleCFBStream(keyPassphrase string) Stream {
	return DefaultProvider.SimpleCFBStream(keyPassphrase)
}

// NewOFBStream creates a new OFB stream cipher with the given key and iv using the DefaultProvider.
//
// The iv will be used as the initial value for the OFB mode.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
//
// Use [SimpleOFBStream] if you are not familiar with these.
// See also: [cipher.NewOFB] for low-level usage.
func NewOFBStream(key, iv Key) Stream {
	return DefaultProvider.NewOFBStream(key, iv)
}

// SimpleOFBStream creates a new AES-256-OFB stream cipher from the given key and iv using the DefaultProvider.
//
// An [Aes256] key for encryption/decryption will be derived from the
// arbitrary keyPassphrase string via scrypt.
//
// The iv will be a random value.
//
// See also: [NewOFBStream] for more control.
func SimpleOFBStream(keyPassphrase string) Stream {
	return DefaultProvider.SimpleOFBStream(keyPassphrase)
}

// NewCTRStream creates a new CTR stream cipher with the given key and iv using the DefaultProvider.
//
// The iv will be used as the initial value for the CTR mode.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
//
// Use [SimpleCTRStream] if you are not familiar with these.
// See also: [cipher.NewCTR] for low-level usage.
func NewCTRStream(key, iv Key) Stream {
	return DefaultProvider.NewCTRStream(key, iv)
}

// SimpleCTRStream creates a new AES-256-CTR stream cipher from the given key and iv using the DefaultProvider.
//
// An [Aes256] key for encryption/decryption will be derived from the
// arbitrary keyPassphrase string via scrypt.
//
// The iv will be a random value.
//
// See also: [NewCTRStream] for more control.
func SimpleCTRStream(keyPassphrase string) Stream {
	return DefaultProvider.SimpleCTRStream(keyPassphrase)
}
