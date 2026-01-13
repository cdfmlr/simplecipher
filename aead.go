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

// TODO: fix(GCM): nonce should be randomly generated for each encryption,
//       add prefix to ciphertext just like iv in other modes.
//       The current nonce key in struct should actually be the additionalData.
//       the ciphertext should be:
//           [ Nonce ] + [ Ciphertext ] + [ Additional ].
//       the interface should be:
//           func SimpleGCM(keyPassphrase, additionalPassphrase string) Block
// TODO: feat(GCM): GCM can support stream.
// TODO: docs(GCM): GCM can be preferred then CTR in docs after these changes,
//       because GCM provides integrity check and it's actually The Gold Standard.

// gcm is the AES-GCM cipher mode implementation for the [Block] interface.
type gcm struct {
	key    Key
	nonce  Key
	config *config
}

var _ Block = (*gcm)(nil)

// newGCM is an internal constructor used by Provider.
func newGCM(key, nonce Key, provider *Provider) Block {
	return &gcm{key: key, nonce: nonce, config: provider}
}

// NewGCM creates a new GCM cipher with the given key and nonce using the DefaultProvider.
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16 or 32 bytes long to select AES-128 or AES-256.
//   - The nonce must be 12 bytes long.
//
// Use [SimpleGCM] if you are not familiar with these.
//
// See also: [cipher.NewGCM] for low-level usage.
func NewGCM(key, nonce Key) Block {
	return DefaultProvider.NewGCM(key, nonce)
}

// SimpleGCM creates a new AES-256-GCM cipher from the given key and nonce using the DefaultProvider.
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
func SimpleGCM(keyPassphrase, noncePassphrase string) Block {
	return DefaultProvider.SimpleGCM(keyPassphrase, noncePassphrase)
}

// Encrypt encrypts the given plaintext using GCM.
// The ciphertext is returned with the provider's StringCodec encoding.
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

	return g.config.StringCodec.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using GCM.
// The ciphertext must be a string encoded with the provider's StringCodec.
func (g *gcm) Decrypt(cipherText string) (plainText string, err error) {
	defer recoverFromPanic(&err)

	ciphertext, err := g.config.StringCodec.DecodeString(cipherText)
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
