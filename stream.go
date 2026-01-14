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
