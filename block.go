package simplecipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"github.com/cdfmlr/simplecipher/pkcs7"
)

// This file implements AES block cipher modes.
//
// Available modes are:
//
//   - CBC (Cipher Block Chaining)
//   - CFB (Cipher Feedback)
//   - OFB (Output Feedback)
//   - CTR (Counter)
//
// See also:
//  - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Confidentiality_only_modes
//  - https://pkg.go.dev/crypto/cipher@go1.23.1#Block

// cbc is the AES-CBC cipher mode implementation for the [Cipher] interface.
type cbc struct {
	key Key
	iv  Key
}

var _ Cipher = (*cbc)(nil)

// NewCBC creates a new CBC cipher with the given key and iv.
//
// The iv will be prepended to the ciphertext during encryption,
// and the first block of the ciphertext will be treated as the IV during decryption.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
//   - The plaintext must be padded to a multiple of [aes.BlockSize] bytes.
//
// Use [SimpleCBC] if you are not familiar with these.
//
// See also: [cipher.NewCBCDecrypter], [cipher.NewCBCEncrypter] for low-level usage.
func NewCBC(key, iv Key) Cipher {
	return &cbc{key: key, iv: iv}
}

// Encrypt encrypts the given plaintext using CBC.
// The ciphertext is returned with [DefaultStringCodec] encoding.
//
// The IV will be prepended to the ciphertext as the first block.
func (c *cbc) Encrypt(plainText string) (cipherText string, err error) {
	defer recoverFromPanic(&err)

	plaintext := []byte(plainText)

	key := c.key.Bytes()
	iv := c.iv.Bytes()

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(plaintext)%aes.BlockSize != 0 {
		return "", ErrPlaintextBlockSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	var ciphertext []byte

	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	copy(ciphertext[:aes.BlockSize], iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return DefaultStringCodec.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using CBC.
// The ciphertext must be a [DefaultStringCodec] string.
//
// The iv prepended to the ciphertext (the first block) will be used.
// And the iv field of the cbc will be ignored.
func (c *cbc) Decrypt(cipherText string) (plainText string, err error) {
	defer recoverFromPanic(&err)

	ciphertext, err := DefaultStringCodec.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	key := c.key.Bytes()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", ErrCipherTextTooShort
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", ErrCipherTextBlockSize
	}

	var iv []byte

	iv = ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// simpleCBC = cbc + random iv + PKCS7 padding plaintext
type simpleCBC struct {
	cbc
}

// SimpleCBC creates a new AES-256-CBC cipher with the given key.
//
// The keyPassphrase parameter can be any arbitrary string. It will be used to
// derive the real key used in the CBC mode via scrypt.
//
// Random iv will be generated for each encryption and prepended to the
// ciphertext.
//
// The plaintext is automatically padded to a multiple of [aes.BlockSize] bytes
// with PKCS7 padding.
//
// See also: [NewCBC] for more control.
func SimpleCBC(keyPassphrase string) Cipher {
	return &simpleCBC{cbc: cbc{key: NewAesKey(keyPassphrase), iv: NewRandomIv()}}
}

func (c *simpleCBC) Encrypt(plainText string) (cipherText string, err error) {
	defer recoverFromPanic(&err)

	paddedText := string(pkcs7.Pad(aes.BlockSize, []byte(plainText)))
	return c.cbc.Encrypt(paddedText)
}

func (c *simpleCBC) Decrypt(cipherText string) (plainText string, err error) {
	defer recoverFromPanic(&err)

	paddedText, err := c.cbc.Decrypt(cipherText)
	if err != nil {
		return "", err
	}
	plaintext, err := pkcs7.Unpad(aes.BlockSize, []byte(paddedText))
	return string(plaintext), err
}

//////// Wrap stream.go cipher to block cipher ////////

// streamToBlock is a wrapper to convert a [Stream] to a Block [Cipher].
//
// It creates byte buffers to store the plaintext and ciphertext,
// and uses the EncryptStream and DecryptStream methods of the [Stream]
// to perform the encryption and decryption.
//
// It also encodes the ciphertext with [DefaultStringCodec] when Encrypting,
// and decodes the ciphertext from a [DefaultStringCodec] string when Decrypting.
type streamToBlock struct {
	Stream
}

var _ Cipher = (*streamToBlock)(nil)

func newStreamToBlock(sc Stream) Cipher {
	return &streamToBlock{Stream: sc}
}

func (s *streamToBlock) Encrypt(plainText string) (cipherText string, err error) {
	defer recoverFromPanic(&err)

	plainTextReader := bytes.NewReader([]byte(plainText))
	cipherTextBuffer := new(bytes.Buffer)

	err = s.EncryptStream(plainTextReader, cipherTextBuffer)
	if err != nil {
		return "", err
	}

	cipherTextBytes := cipherTextBuffer.Bytes()
	encodedCipherText := DefaultStringCodec.EncodeToString(cipherTextBytes)

	return encodedCipherText, nil
}

func (s *streamToBlock) Decrypt(cipherText string) (plainText string, err error) {
	defer recoverFromPanic(&err)

	cipherTextBytes, err := DefaultStringCodec.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	plainTextBuffer := new(bytes.Buffer)

	err = s.DecryptStream(bytes.NewReader(cipherTextBytes), plainTextBuffer)
	if err != nil {
		return "", err
	}

	plainTextBytes := plainTextBuffer.Bytes()

	return string(plainTextBytes), nil
}

// NewCFB creates a new CFB cipher with the given key and iv.
//
// The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
// The iv must be [aes.BlockSize] bytes long.
//
// The iv will be prepended to the ciphertext during encryption,
// and the first block of the ciphertext will be treated as the IV during decryption.
//
// Use SimpleCFB if you are not familiar with this.
//
// See also: [cipher.NewCFBDecrypter], [cipher.NewCFBEncrypter] for low-level usage.
func NewCFB(key, iv Key) Cipher {
	return newStreamToBlock(NewCFBStream(key, iv))
}

// SimpleCFB creates a new AES-256-CFB cipher with a key derived from
// the given keyPassphrase and a random iv prepended to the ciphertext.
//
// See also: [NewCFB] for more control.
func SimpleCFB(keyPassphrase string) Cipher {
	return newStreamToBlock(SimpleCFBStream(keyPassphrase))
}

// NewOFB creates a new OFB cipher with the given key and iv.
//
// The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
// The iv must be [aes.BlockSize] bytes long.
//
// The iv will be prepended to the ciphertext during encryption,
// and the first block of the ciphertext will be treated as the IV during decryption.
//
// Use [SimpleOFB] if you are not familiar with this.
//
// See also: [cipher.NewOFB] for low-level usage.
func NewOFB(key, iv Key) Cipher {
	return newStreamToBlock(NewOFBStream(key, iv))
}

// SimpleOFB creates a new AES-256-OFB cipher with a key derived from
// the given keyPassphrase and a random iv prepended to the ciphertext.
//
// See also: [NewOFB] for more control.
func SimpleOFB(keyPassphrase string) Cipher {
	return newStreamToBlock(SimpleOFBStream(keyPassphrase))
}

// NewCTR creates a new CTR cipher with the given key and iv.
//
// The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
// The iv must be [aes.BlockSize] bytes long.
//
// The iv will be prepended to the ciphertext during encryption,
// and the first block of the ciphertext will be treated as the IV during decryption.
//
// Use [SimpleCTR] if you are not familiar with this.
//
// See also: [cipher.NewCTR] for low-level usage.
func NewCTR(key, iv Key) Cipher {
	return newStreamToBlock(NewCTRStream(key, iv))
}

// SimpleCTR creates a new AES-256-CTR cipher with a key derived from
// the given keyPassphrase and a random iv prepended to the ciphertext.
//
// See also: [NewCTR] for more control.
func SimpleCTR(keyPassphrase string) Cipher {
	return newStreamToBlock(SimpleCTRStream(keyPassphrase))
}
