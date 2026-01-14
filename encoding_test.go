package simplecipher

import (
	"testing"

	"github.com/cdfmlr/simplecipher/v2/codec"
)

// Fuzz the codec here in help of fuzzall_test.go impl to
// bypass the go test limitation that:
// cannot use -fuzz flag with multiple packages

func FuzzStringCodecs(f *testing.F) {
	codecs := map[string]codec.StringCodec{
		"Nop":       codec.Nop,
		"Hex":       codec.Hex,
		"Base64Std": codec.Base64Std,
		"Base64URL": codec.Base64URL,
		"Base32Std": codec.Base32Std,
		"Base32Hex": codec.Base32Hex,
	}

	// src: bytes
	f.Add([]byte("src"))
	f.Add([]byte(""))
	f.Add([]byte("👋，世界！"))

	f.Fuzz(func(t *testing.T, src []byte) {
		for name, codec := range codecs {
			encoded := codec.EncodeToString(src)
			decoded, err := codec.DecodeString(encoded)
			if err != nil {
				t.Errorf("%s.DecodeString(%s) = %v", name, encoded, err)
			}
			if string(decoded) != string(src) {
				t.Errorf("%s.DecodeString(%s) = %s, want %s", name, encoded, decoded, src)
			}
		}
	})
}
