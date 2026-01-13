package simplecipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
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

// ////// GCM Stream ////////

// gcmStream is the AES-GCM cipher mode implementation for the [Stream] interface.
// Unlike the [gcm] Block implementation, gcmStream works with io.Reader and io.Writer.
type gcmStream struct {
	key            Key
	nonce          Key
	additionalData Key
}

var _ Stream = (*gcmStream)(nil)

// newGCMStream is an internal constructor for gcmStream.
func newGCMStream(key, nonce, additionalData Key) Stream {
	return &gcmStream{key: key, nonce: nonce, additionalData: additionalData}
}

// EncryptStream encrypts the given plaintext from the reader using GCM.
// The ciphertext is written to the given writer without encoding.
// The format is: nonce + encrypted_data + tag
func (g *gcmStream) EncryptStream(plainText io.Reader, cipherText io.Writer) (err error) {
	defer recoverFromPanic(&err)

	key := g.key.Bytes()
	nonce := g.nonce.Bytes()
	ad := g.additionalData.Bytes()

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNewAesCipher, err)
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, NonceSize)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNewAesCipher, err)
	}

	// Read all plaintext data
	plaintext, err := io.ReadAll(plainText)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCopy, err)
	}

	// Encrypt the plaintext with GCM
	// the ret ciphertext contains nonce + ciphertext + tag
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, ad)

	// Write the complete ciphertext (nonce + encrypted data + tag) to the writer
	_, err = cipherText.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCopy, err)
	}

	return nil
}

// DecryptStream decrypts the given ciphertext from the reader using GCM.
// The ciphertext read from the given reader should not be encoded.
// The format is: nonce + encrypted_data + tag
func (g *gcmStream) DecryptStream(cipherText io.Reader, plainText io.Writer) (err error) {
	defer recoverFromPanic(&err)

	key := g.key.Bytes()
	ad := g.additionalData.Bytes()

	// Read all ciphertext data
	ciphertext, err := io.ReadAll(cipherText)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCopy, err)
	}

	// Extract nonce from the beginning of the ciphertext
	if len(ciphertext) < NonceSize {
		return fmt.Errorf("%w: ciphertext too short to contain nonce", ErrCipherTextTooShort)
	}

	extractedNonce, actualCiphertext := ciphertext[:NonceSize], ciphertext[NonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNewAesCipher, err)
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, NonceSize)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNewAesCipher, err)
	}

	// Decrypt and verify the ciphertext
	plaintext, err := aesgcm.Open(nil, extractedNonce, actualCiphertext, ad)
	if err != nil {
		return fmt.Errorf("gcm decryption failed: %w", err)
	}

	// Write the plaintext to the writer
	_, err = plainText.Write(plaintext)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCopy, err)
	}

	return nil
}

// ////// Exported Constructors ////////

// NewGCMStream creates a new GCM stream cipher with the given key, nonce and additional data using the DefaultProvider.
//
// The nonce will be prepended to the ciphertext during encryption,
// and the first NonceSize bytes of the ciphertext will be treated as the nonce during decryption.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16 or 32 bytes long to select AES-128 or AES-256.
//   - The nonce must be 12 bytes long.
//
// Use [SimpleGCMStream] if you are not familiar with these.
// See also: [cipher.NewGCM] for low-level usage.
func NewGCMStream(key, nonce, additionalData Key) Stream {
	return DefaultProvider.NewGCMStream(key, nonce, additionalData)
}

// SimpleGCMStream creates a new AES-256-GCM stream cipher from the given key and additional data using the DefaultProvider.
//
// The keyPassphrase and additionalPassphrase parameters can be any arbitrary strings.
// SimpleGCMStream will derive the real key, nonce and additionalData used in the GCM mode
// from these passphrases via DefaultProvider's KeyDerivation function.
//
// The nonce used in this SimpleGCMStream implementation is randomly generated and prepended to the ciphertext.
//
// See also: [NewGCMStream] for more control.
func SimpleGCMStream(keyPassphrase, additionalPassphrase string) Stream {
	return DefaultProvider.SimpleGCMStream(keyPassphrase, additionalPassphrase)
}
