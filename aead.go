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

// TODO: feat(GCM): GCM can support stream.

// gcm is the AES-GCM cipher mode implementation for the [Block] interface.
type gcm struct {
	key            Key
	nonce          Key
	additionalData Key
	config         *config
}

var _ Block = (*gcm)(nil)

// newGCM is an internal constructor used by Provider.
func newGCM(key, nonce, additionalData Key, provider *Provider) Block {
	return &gcm{key: key, nonce: nonce, additionalData: additionalData, config: provider}
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
func NewGCM(key, nonce, additionalData Key) Block {
	return DefaultProvider.NewGCM(key, nonce, additionalData)
}

// SimpleGCM creates a new AES-256-GCM cipher from the given key and additional
// data using the DefaultProvider.
//
// The keyPassphrase and additionalPassphrase parameters can be any arbitrary strings.
// SimpleGCM will derive the real key, nonce and additionalData used in the GCM mode
// from the these passphrases via DefaultProvider's KeyDerivation function.
//
// The nonce used in this SimpleGCM implementation is randomly generated.
//
// See also: [NewGCM]
func SimpleGCM(keyPassphrase, additionalPassphrase string) Block {
	return DefaultProvider.SimpleGCM(keyPassphrase, additionalPassphrase)
}

// Encrypt encrypts the given plaintext using GCM.
// The ciphertext is returned with the provider's StringCodec encoding.
func (g *gcm) Encrypt(plainText string) (cipherText string, err error) {
	defer recoverFromPanic(&err)

	plaintext := []byte(plainText)
	key := g.key.Bytes()
	nonce := g.nonce.Bytes()
	ad := g.additionalData.Bytes()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// aesgcm, err := cipher.NewGCM(block)
	aesgcm, err := cipher.NewGCMWithNonceSize(block, NonceSize)
	if err != nil {
		return "", err
	}

	// fmt.Printf("DBG GCM Encrypt: key=%x nonce=%x ad=%x\n", key, nonce, ad)

	// the ret ciphertext contains nonce + ciphertext + tag
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, ad)

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
	ad := g.additionalData.Bytes()

	extractedNonce, actualCiphertext := ciphertext[:NonceSize], ciphertext[NonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, NonceSize)
	if err != nil {
		return "", err
	}

	// fmt.Printf("DBG GCM Decrypt: key=%x nonce=%x ad=%x\n", key, extractedNonce, ad)

	plaintext, err := aesgcm.Open(nil, extractedNonce, actualCiphertext, ad)
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
