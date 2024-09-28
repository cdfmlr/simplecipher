package simplecipher

import "testing"

func FuzzStringCodecs(f *testing.F) {
	codecs := map[string]StringCodec{
		"NopCodec":       NopCodec,
		"HexCodec":       HexCodec,
		"Base64StdCodec": Base64StdCodec,
		"Base64URLCodec": Base64URLCodec,
		"Base32StdCodec": Base32StdCodec,
		"Base32HexCodec": Base32HexCodec,
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
