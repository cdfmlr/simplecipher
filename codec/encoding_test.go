package codec

import (
	"testing"
)

func TestNopCodec(t *testing.T) {
	tests := []struct {
		name string
		src  []byte
	}{
		{
			name: "empty bytes",
			src:  []byte{},
		},
		{
			name: "simple string",
			src:  []byte("hello"),
		},
		{
			name: "string with special characters",
			src:  []byte("!@#$%^&*()"),
		},
		{
			name: "unicode string",
			src:  []byte("👋，世界！"),
		},
		{
			name: "binary data",
			src:  []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Nop.EncodeToString(tt.src)
			if encoded != string(tt.src) {
				t.Errorf("EncodeToString() = %q, want %q", encoded, string(tt.src))
			}

			decoded, err := Nop.DecodeString(encoded)
			if err != nil {
				t.Errorf("DecodeString() error = %v, want nil", err)
			}
			if string(decoded) != string(tt.src) {
				t.Errorf("DecodeString() = %q, want %q", string(decoded), string(tt.src))
			}
		})
	}
}

func TestHexCodec(t *testing.T) {
	tests := []struct {
		name    string
		src     []byte
		encoded string
	}{
		{
			name:    "empty bytes",
			src:     []byte{},
			encoded: "",
		},
		{
			name:    "simple string",
			src:     []byte("hello"),
			encoded: "68656c6c6f",
		},
		{
			name:    "single byte",
			src:     []byte{0xFF},
			encoded: "ff",
		},
		{
			name:    "all bytes",
			src:     []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
			encoded: "000102fffefd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Hex.EncodeToString(tt.src)
			if encoded != tt.encoded {
				t.Errorf("EncodeToString() = %q, want %q", encoded, tt.encoded)
			}

			decoded, err := Hex.DecodeString(encoded)
			if err != nil {
				t.Errorf("DecodeString() error = %v, want nil", err)
			}
			if string(decoded) != string(tt.src) {
				t.Errorf("DecodeString() = %q, want %q", string(decoded), string(tt.src))
			}
		})
	}

	t.Run("invalid hex string", func(t *testing.T) {
		_, err := Hex.DecodeString("ZZZZ")
		if err == nil {
			t.Error("DecodeString() error = nil, want error")
		}
	})
}

func TestBase64StdCodec(t *testing.T) {
	tests := []struct {
		name    string
		src     []byte
		encoded string
	}{
		{
			name:    "empty bytes",
			src:     []byte{},
			encoded: "",
		},
		{
			name:    "simple string",
			src:     []byte("hello"),
			encoded: "aGVsbG8=",
		},
		{
			name:    "single byte",
			src:     []byte{0xFF},
			encoded: "/w==",
		},
		{
			name:    "all bytes",
			src:     []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
			encoded: "AAEC//79",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Base64Std.EncodeToString(tt.src)
			if encoded != tt.encoded {
				t.Errorf("EncodeToString() = %q, want %q", encoded, tt.encoded)
			}

			decoded, err := Base64Std.DecodeString(encoded)
			if err != nil {
				t.Errorf("DecodeString() error = %v, want nil", err)
			}
			if string(decoded) != string(tt.src) {
				t.Errorf("DecodeString() = %q, want %q", string(decoded), string(tt.src))
			}
		})
	}

	t.Run("invalid base64 string", func(t *testing.T) {
		_, err := Base64Std.DecodeString("!!!!")
		if err == nil {
			t.Error("DecodeString() error = nil, want error")
		}
	})
}

func TestBase64URLCodec(t *testing.T) {
	tests := []struct {
		name    string
		src     []byte
		encoded string
	}{
		{
			name:    "empty bytes",
			src:     []byte{},
			encoded: "",
		},
		{
			name:    "simple string",
			src:     []byte("hello"),
			encoded: "aGVsbG8=",
		},
		{
			name:    "bytes that differ in URL encoding",
			src:     []byte{0xFB, 0xFF, 0xFE},
			encoded: "-__-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Base64URL.EncodeToString(tt.src)
			if encoded != tt.encoded {
				t.Errorf("EncodeToString() = %q, want %q", encoded, tt.encoded)
			}

			decoded, err := Base64URL.DecodeString(encoded)
			if err != nil {
				t.Errorf("DecodeString() error = %v, want nil", err)
			}
			if string(decoded) != string(tt.src) {
				t.Errorf("DecodeString() = %q, want %q", string(decoded), string(tt.src))
			}
		})
	}

	t.Run("invalid base64 URL string", func(t *testing.T) {
		_, err := Base64URL.DecodeString("!!!!")
		if err == nil {
			t.Error("DecodeString() error = nil, want error")
		}
	})
}

func TestBase32StdCodec(t *testing.T) {
	tests := []struct {
		name    string
		src     []byte
		encoded string
	}{
		{
			name:    "empty bytes",
			src:     []byte{},
			encoded: "",
		},
		{
			name:    "simple string",
			src:     []byte("hello"),
			encoded: "NBSWY3DP",
		},
		{
			name:    "single byte",
			src:     []byte("a"),
			encoded: "ME======",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Base32Std.EncodeToString(tt.src)
			if encoded != tt.encoded {
				t.Errorf("EncodeToString() = %q, want %q", encoded, tt.encoded)
			}

			decoded, err := Base32Std.DecodeString(encoded)
			if err != nil {
				t.Errorf("DecodeString() error = %v, want nil", err)
			}
			if string(decoded) != string(tt.src) {
				t.Errorf("DecodeString() = %q, want %q", string(decoded), string(tt.src))
			}
		})
	}

	t.Run("invalid base32 string", func(t *testing.T) {
		_, err := Base32Std.DecodeString("!!!!")
		if err == nil {
			t.Error("DecodeString() error = nil, want error")
		}
	})
}

func TestBase32HexCodec(t *testing.T) {
	tests := []struct {
		name    string
		src     []byte
		encoded string
	}{
		{
			name:    "empty bytes",
			src:     []byte{},
			encoded: "",
		},
		{
			name:    "simple string",
			src:     []byte("hello"),
			encoded: "D1IMOR3F",
		},
		{
			name:    "single byte",
			src:     []byte("a"),
			encoded: "C4======",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Base32Hex.EncodeToString(tt.src)
			if encoded != tt.encoded {
				t.Errorf("EncodeToString() = %q, want %q", encoded, tt.encoded)
			}

			decoded, err := Base32Hex.DecodeString(encoded)
			if err != nil {
				t.Errorf("DecodeString() error = %v, want nil", err)
			}
			if string(decoded) != string(tt.src) {
				t.Errorf("DecodeString() = %q, want %q", string(decoded), string(tt.src))
			}
		})
	}

	t.Run("invalid base32 hex string", func(t *testing.T) {
		_, err := Base32Hex.DecodeString("!!!!")
		if err == nil {
			t.Error("DecodeString() error = nil, want error")
		}
	})
}

func TestAllCodecsRoundTrip(t *testing.T) {
	codecs := []struct {
		name  string
		codec StringCodec
	}{
		{"Nop", Nop},
		{"Hex", Hex},
		{"Base64Std", Base64Std},
		{"Base64URL", Base64URL},
		{"Base32Std", Base32Std},
		{"Base32Hex", Base32Hex},
	}

	testCases := []struct {
		name string
		src  []byte
	}{
		{"empty", []byte{}},
		{"ascii", []byte("hello")},
		{"binary", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
		{"unicode", []byte("👋，世界！")},
		{"long text", []byte("The quick brown fox jumps over the lazy dog")},
	}

	for _, codec := range codecs {
		for _, tc := range testCases {
			t.Run(codec.name+"/"+tc.name, func(t *testing.T) {
				encoded := codec.codec.EncodeToString(tc.src)
				decoded, err := codec.codec.DecodeString(encoded)
				if err != nil {
					t.Errorf("DecodeString() error = %v, want nil", err)
				}
				if string(decoded) != string(tc.src) {
					t.Errorf("DecodeString() = %q, want %q", string(decoded), string(tc.src))
				}
			})
		}
	}
}

func TestStringCodecInterface(t *testing.T) {
	var _ StringCodec = Nop
	var _ StringCodec = Hex
	var _ StringCodec = Base64Std
	var _ StringCodec = Base64URL
	var _ StringCodec = Base32Std
	var _ StringCodec = Base32Hex
}

func BenchmarkHexCodec(b *testing.B) {
	src := []byte("hello world")
	b.Run("EncodeToString", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hex.EncodeToString(src)
		}
	})
	b.Run("DecodeString", func(b *testing.B) {
		encoded := Hex.EncodeToString(src)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = Hex.DecodeString(encoded)
		}
	})
}

func BenchmarkBase64StdCodec(b *testing.B) {
	src := []byte("hello world")
	b.Run("EncodeToString", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Base64Std.EncodeToString(src)
		}
	})
	b.Run("DecodeString", func(b *testing.B) {
		encoded := Base64Std.EncodeToString(src)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = Base64Std.DecodeString(encoded)
		}
	})
}

func BenchmarkBase32StdCodec(b *testing.B) {
	src := []byte("hello world")
	b.Run("EncodeToString", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Base32Std.EncodeToString(src)
		}
	})
	b.Run("DecodeString", func(b *testing.B) {
		encoded := Base32Std.EncodeToString(src)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = Base32Std.DecodeString(encoded)
		}
	})
}
