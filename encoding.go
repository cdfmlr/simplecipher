package simplecipher

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
)

// This file provides encoding and decoding functions for Cipher ciphertexts.
// Available encoding formats are:
//
//   - Hex
//   - Base64
//   - Base32

type StringCodec interface {
	EncodeToString(src []byte) string
	DecodeString(s string) ([]byte, error)
}

// DefaultStringCodec is the default [StringCodec] used by [Cipher] implementations.
// It is set to [HexCodec] by default.
//
// You can change it to [Base64StdCodec], [Base64URLCodec], [Base32StdCodec], or [Base32HexCodec]:
//
//	simplecipher.DefaultStringCodec = simplecipher.Base64StdCodec
//	ciphertext := simplecipher.SimpleCTR("strong-key").Encrypt("plaintext")
//	fmt.Println(ciphertext) // "YmFzZTY0c2VjcmV0"
//
// If encoding and decoding are not needed, or you want to handle it yourself,
// set it to [NopCodec]:
//
//	simplecipher.DefaultStringCodec = simplecipher.NopCodec
//	ciphertext := simplecipher.SimpleCTR("strong-key").Encrypt("plaintext")
//	rawCiphertextBytes := []byte(ciphertext) // rawCiphertextBytes is now the ciphertext bytes output by the algorithm without encoding.
var DefaultStringCodec StringCodec = HexCodec

type nopCodec struct{}

func (nopCodec) EncodeToString(src []byte) string {
	return string(src)
}

func (nopCodec) DecodeString(s string) ([]byte, error) {
	return []byte(s), nil
}

// NopCodec does not encode or decode the input.
// It just converts the type from []byte to string and vice versa.
var NopCodec StringCodec = nopCodec{}

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

// HexCodec encodes and decodes using hexadecimal encoding:
//   - alphabet is "0123456789abcdef"
var HexCodec StringCodec = hexCodec{}

// base64Codec is a StringCodec that encodes and decodes using base64 encoding.
type base64Codec struct {
	*base64.Encoding
}

// Base64StdCodec encodes and decodes using standard base64 encoding:
//   - alphabet is "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
//   - padding character is '='
var Base64StdCodec StringCodec = base64Codec{base64.StdEncoding}

// Base64URLCodec encodes and decodes using URL-compatible base64 encoding:
//   - alphabet is "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
//   - padding character is '='
var Base64URLCodec StringCodec = base64Codec{base64.URLEncoding}

type base32Codec struct {
	*base32.Encoding
}

// Base32StdCodec encodes and decodes using standard base32 encoding:
//   - alphabet is "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
//   - padding character is '='
var Base32StdCodec StringCodec = base32Codec{base32.StdEncoding}

// Base32HexCodec encodes and decodes using base32 encoding with extended hex alphabet:
//   - alphabet is "0123456789ABCDEFGHIJKLMNOPQRSTUV"
//   - padding character is '='
var Base32HexCodec StringCodec = base32Codec{base32.HexEncoding}
