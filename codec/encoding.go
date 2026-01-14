package codec

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
)

// This file provides encoding and decoding functions for Block ciphertexts.
// Available encoding formats are:
//
//   - Hex
//   - Base64
//   - Base32

// StringCodec is an interface that provides encoding and decoding functions
// for Block ciphertexts.
type StringCodec interface {
	EncodeToString(src []byte) string
	DecodeString(s string) ([]byte, error)
}

// DefaultStringCodec is the default [StringCodec] used by [Block] implementations.
// It is set to [Hex] by default.
//
// You can change it to [Base64Std], [Base64URL], [Base32Std], or [Base32Hex]:
//
//	simplecipher.DefaultStringCodec = simplecipher.Base64Std
//	ciphertext := simplecipher.SimpleCTR("strong-key").Encrypt("plaintext")
//	fmt.Println(ciphertext) // "YmFzZTY0c2VjcmV0"
//
// If encoding and decoding are not needed, or you want to handle it yourself,
// set it to [Nop]:
//
//	simplecipher.DefaultStringCodec = simplecipher.Nop
//	ciphertext := simplecipher.SimpleCTR("strong-key").Encrypt("plaintext")
//	rawCiphertextBytes := []byte(ciphertext) // rawCiphertextBytes is now the ciphertext bytes output by the algorithm without encoding.
//
// See also: [Hex], [Base64Std], [Base64URL], [Base32Std], [Base32Hex], [Nop]
var DefaultStringCodec StringCodec = Hex

type nopCodec struct{}

func (nopCodec) EncodeToString(src []byte) string {
	return string(src)
}

func (nopCodec) DecodeString(s string) ([]byte, error) {
	return []byte(s), nil
}

// Nop does not encode or decode the input.
// It just converts the type from []byte to string and vice versa.
var Nop StringCodec = nopCodec{}

// hexCodec is a StringCodec that encodes and decodes using hexadecimal encoding.
type hexCodec struct{}

// EncodeToString returns the hexadecimal encoding of src.
func (hexCodec) EncodeToString(src []byte) string {
	return hex.EncodeToString(src)
}

// DecodeString decodes a hexadecimal encoded string and returns the decoded bytes.
func (hexCodec) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// Hex encodes and decodes using hexadecimal encoding:
//   - alphabet is "0123456789abcdef"
//
// See also: [hex.EncodeToString], [hex.DecodeString]
var Hex StringCodec = hexCodec{}

// base64Codec is a StringCodec that encodes and decodes using base64 encoding.
type base64Codec struct {
	*base64.Encoding
}

// Base64Std encodes and decodes using standard base64 encoding:
//   - alphabet is "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
//   - padding character is '='
//
// See also: [base64.StdEncoding]
var Base64Std StringCodec = base64Codec{base64.StdEncoding}

// Base64URL encodes and decodes using URL-compatible base64 encoding:
//   - alphabet is "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
//   - padding character is '='
//
// See also: [base64.URLEncoding]
var Base64URL StringCodec = base64Codec{base64.URLEncoding}

type base32Codec struct {
	*base32.Encoding
}

// Base32Std encodes and decodes using standard base32 encoding:
//   - alphabet is "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
//   - padding character is '='
//
// See also: [base32.StdEncoding]
var Base32Std StringCodec = base32Codec{base32.StdEncoding}

// Base32Hex encodes and decodes using base32 encoding with extended hex alphabet:
//   - alphabet is "0123456789ABCDEFGHIJKLMNOPQRSTUV"
//   - padding character is '='
//
// See also: [base32.HexEncoding]
var Base32Hex StringCodec = base32Codec{base32.HexEncoding}
