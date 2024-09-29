package simplecipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// This file implements AES cipher modes providing authenticated encryption with
// associated data.
//
// Available modes are:
//
//  - GCM (Galois/Counter Mode) with default standard nonce & tag sizes.
//
// See also:
//  - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Authenticated_encryption_with_additional_data_(AEAD)_modes
//  - https://pkg.go.dev/crypto/cipher@go1.23.1#AEAD

// gcm is the AES-GCM cipher mode implementation for the [Cipher] interface.
type gcm struct {
	key   Key
	nonce Key
}

var _ Cipher = (*gcm)(nil)

// NewGCM creates a new GCM cipher with the given key and nonce.
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16 or 32 bytes long to select AES-128 or AES-256.
//   - The nonce must be 12 bytes long.
//
// Use [SimpleGCM] if you are not familiar with these.
//
// See also: [cipher.NewGCM] for low-level usage.
func NewGCM(key, nonce Key) Cipher {
	return &gcm{key: key, nonce: nonce}
}

// SimpleGCM creates a new AES-256-GCM cipher from the given key and nonce.
//
// The keyPassphrase and noncePassphrase parameters can be any arbitrary strings.
// SimpleGCM will derive the real key and nonce used in the GCM mode
// from the these passphrases via scrypt.
//
// Attention: SimpleGCM is not compatible with other libraries,
// because it uses a custom key derivation function.
// You can only decrypt the encrypted ciphertext with the same version of
// SimpleGCM and the same passphrases passed to it.
//
// See also: [NewGCM]
func SimpleGCM(keyPassphrase, noncePassphrase string) Cipher {
	return NewGCM(NewAesKey(keyPassphrase), NewNonce(noncePassphrase))
}

// Encrypt encrypts the given plaintext using GCM.
// The ciphertext is returned with [DefaultStringCodec] encoding.
func (g *gcm) Encrypt(plainText string) (cipherText string, err error) {
	defer recoverFromPanic(&err)

	plaintext := []byte(plainText)
	key := g.key.Bytes()
	nonce := g.nonce.Bytes()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	return DefaultStringCodec.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using GCM.
// The ciphertext must be a [DefaultStringCodec] string.
func (g *gcm) Decrypt(cipherText string) (plainText string, err error) {
	defer recoverFromPanic(&err)

	ciphertext, err := DefaultStringCodec.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	key := g.key.Bytes()
	nonce := g.nonce.Bytes()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// recoverFromPanic recovers from a panic and sets the error to the given pointer.
func recoverFromPanic(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("%w: %v", ErrPanic, r)
	}
}
