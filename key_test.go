package simplecipher

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/cdfmlr/simplecipher/v2/kdf"
)

func TestBytes_Bytes(t *testing.T) {
	// provider does not determine bytesKey behavior

	tests := []struct {
		name string
		k    bytesKey
		want []byte
	}{
		{
			name: "empty",
			k:    bytesKey{},
			want: []byte{},
		},
		{
			name: "nil",
			k:    bytesKey(nil),
			want: nil,
		},
		{
			name: "common",
			k:    bytesKey{1, 2, 3},
			want: []byte{1, 2, 3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.k.Bytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("bytesKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestString_Bytes(t *testing.T) {
	// provider does not determine stringKey behavior

	tests := []struct {
		name string
		k    Key
		want []byte
	}{
		{
			name: "empty",
			k:    String(""),
			want: []byte{},
		},
		{
			name: "common",
			k:    String("hello"),
			want: []byte("hello"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.k.Bytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("stringKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_keyGen_Bytes(t *testing.T) {
	// these tests are against different KDFs and other parameters.
	type fields struct {
		Passphrase string
		Len        KeyLen
		Salt       string
		KDF        KeyDerivation
	}
	tests := []struct {
		name   string
		fields fields
		want   string // hex encoded bytes
	}{
		{
			name: "zero",
			fields: fields{
				Passphrase: "",
				Len:        0,
				Salt:       "",
				KDF:        kdf.NewScrypt(2048, 8, 1),
			},
			want: "",
		},
		{
			name: "lessThanZero",
			fields: fields{
				Passphrase: "any",
				Len:        -1,
				Salt:       "",
				KDF:        kdf.NewScrypt(2048, 8, 1),
			},
			want: "",
		},
		{
			name: "aes128",
			fields: fields{
				Passphrase: "hello, world",
				Len:        Aes128,
				Salt:       "testsalt",
				KDF:        kdf.NewScrypt(2048, 8, 1),
			},
			want: "4f1db40b0cd47e1d2639da8c95ef6d1b",
		},
		{
			name: "aes192",
			fields: fields{
				Passphrase: "hello, world",
				Len:        Aes192,
				Salt:       "testsalt",
				KDF:        kdf.NewScrypt(2048, 8, 1),
			},
			want: "4f1db40b0cd47e1d2639da8c95ef6d1b65e706e6e211680e",
		},
		{
			name: "aes256",
			fields: fields{
				Passphrase: "hello, world",
				Len:        Aes256,
				Salt:       "testsalt",
				KDF:        kdf.NewScrypt(2048, 8, 1),
			},
			want: "4f1db40b0cd47e1d2639da8c95ef6d1b65e706e6e211680eeb14dc23ce8de545",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := keyGen{
				Passphrase:    tt.fields.Passphrase,
				Len:           tt.fields.Len,
				Salt:          tt.fields.Salt,
				KeyDerivation: tt.fields.KDF,
			}
			wantBytes, _ := hex.DecodeString(tt.want)
			got := k.Bytes()
			if !reflect.DeepEqual(got, wantBytes) {
				t.Errorf("Bytes() = %x, want %x", got, tt.want)
			}
			if tt.want == "" && len(got) != 0 {
				t.Errorf("Bytes() = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestNewAesKey(t *testing.T) {
	provider := testProvider()

	type args struct {
		passphrase string
		options    []KeyGenOption
	}
	tests := []struct {
		name      string
		args      args
		wantBytes string // hex encoded bytes
	}{
		{
			name: "empty",
			args: args{
				passphrase: "",
			},
			wantBytes: "71fca1d2ac9cc7c23b1c5567aeb83df3055aedb58c4f4fe4ec0089aed7869e79",
		},
		{
			name: "helloworld_aes256",
			args: args{
				passphrase: "hello, world",
			},
			wantBytes: "4f1db40b0cd47e1d2639da8c95ef6d1b65e706e6e211680eeb14dc23ce8de545",
		},
		{
			name: "helloworld_aes128",
			args: args{
				passphrase: "hello, world",
				options: []KeyGenOption{
					WithLen(Aes128),
				},
			},
			wantBytes: "4f1db40b0cd47e1d2639da8c95ef6d1b",
		},
		{
			name: "helloworld_aes192",
			args: args{
				passphrase: "hello, world",
				options: []KeyGenOption{
					WithLen(Aes192),
				},
			},
			wantBytes: "4f1db40b0cd47e1d2639da8c95ef6d1b65e706e6e211680e",
		},
		{
			name: "helloworld_aes256_salt",
			args: args{
				passphrase: "hello, world",
				options: []KeyGenOption{
					WithSalt("custom salt"),
				},
			},
			wantBytes: "ce5c691766c31c558f54aef88785963e04301e766883a093bdd898247de79450",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kg := provider.NewAesKey(tt.args.passphrase, tt.args.options...)
			got := kg.Bytes()
			gotHex := hex.EncodeToString(got)

			if !reflect.DeepEqual(gotHex, tt.wantBytes) {
				t.Errorf("NewAesKey().Bytes() = %v, want %v", gotHex, tt.wantBytes)
			}
		})
	}
}

func TestNewNonce(t *testing.T) {
	provider := testProvider()

	type args struct {
		passphrase string
		options    []KeyGenOption
	}
	tests := []struct {
		name      string
		args      args
		wantBytes string // hex encoded bytes
	}{
		{
			name: "empty",
			args: args{
				passphrase: "",
			},
			wantBytes: "71fca1d2ac9cc7c23b1c5567",
		},
		{
			name: "helloworld",
			args: args{
				passphrase: "hello, world",
			},
			wantBytes: "4f1db40b0cd47e1d2639da8c",
		},
		{
			name: "custom_len",
			args: args{
				passphrase: "hello, world",
				options: []KeyGenOption{
					WithLen(16),
				},
			},
			wantBytes: "4f1db40b0cd47e1d2639da8c95ef6d1b",
		},
		{
			name: "custom_salt",
			args: args{
				passphrase: "hello, world",
				options: []KeyGenOption{
					WithSalt("custom salt"),
				},
			},
			wantBytes: "ce5c691766c31c558f54aef8",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kg := provider.NewNonce(tt.args.passphrase, tt.args.options...)
			got := kg.Bytes()
			gotHex := hex.EncodeToString(got)

			if !reflect.DeepEqual(gotHex, tt.wantBytes) {
				t.Errorf("NewNonce().Bytes() = %v, want %v", gotHex, tt.wantBytes)
			}
		})
	}
}

func TestNewIv(t *testing.T) {
	provider := testProvider()

	type args struct {
		passphrase string
		options    []KeyGenOption
	}
	tests := []struct {
		name      string
		args      args
		wantBytes string // hex encoded bytes
	}{
		{
			name: "empty",
			args: args{
				passphrase: "",
			},
			wantBytes: "71fca1d2ac9cc7c23b1c5567aeb83df3",
		},
		{
			name: "helloworld",
			args: args{
				passphrase: "hello, world",
			},
			wantBytes: "4f1db40b0cd47e1d2639da8c95ef6d1b",
		},
		{
			name: "custom_len",
			args: args{
				passphrase: "hello, world",
				options: []KeyGenOption{
					WithLen(16),
				},
			},
			wantBytes: "4f1db40b0cd47e1d2639da8c95ef6d1b",
		},
		{
			name: "custom_salt",
			args: args{
				passphrase: "hello, world",
				options: []KeyGenOption{
					WithSalt("custom salt"),
				},
			},
			wantBytes: "ce5c691766c31c558f54aef88785963e",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kg := provider.NewIv(tt.args.passphrase, tt.args.options...)
			got := kg.Bytes()
			gotHex := hex.EncodeToString(got)

			if !reflect.DeepEqual(gotHex, tt.wantBytes) {
				t.Errorf("NewNonce().Bytes() = %v, want %v", gotHex, tt.wantBytes)
			}
		})
	}
}

func TestNewRandomIv(t *testing.T) {
	provider := testProvider()

	iv1 := provider.NewRandomIv()
	iv2 := provider.NewRandomIv()

	if reflect.DeepEqual(iv1.Bytes(), iv2.Bytes()) {
		t.Errorf("NewRandomIv() = %v, want random", iv1.Bytes())
	}
	// t.Logf("iv1: %x, iv2: %x", iv1.Bytes(), iv2.Bytes())
}

func TestDefaultNewRandomIv(t *testing.T) {
	iv1 := NewRandomIv()
	iv2 := NewRandomIv()

	if reflect.DeepEqual(iv1.Bytes(), iv2.Bytes()) {
		t.Errorf("NewRandomIv() = %v, want random", iv1.Bytes())
	}
	// t.Logf("iv1: %x, iv2: %x", iv1.Bytes(), iv2.Bytes())
}

func TestKeyGen_Option_WithPassphrase(t *testing.T) {
	p := testProvider()

	k1 := p.NewAesKey("pass-1").Bytes()
	k2 := p.NewAesKey("pass-2").Bytes()
	if reflect.DeepEqual(k1, k2) {
		t.Fatalf("keys with different passphrases should not be equal: got NewAesKey(%q)=%x, NewAesKey(%q)=%x", "pass-1", k1, "pass-2", k2)
	}

	kwpo := p.NewAesKey("pass-1", WithPassphrase("pass-2"))
	kg := kwpo.(*keyGen)
	if kg.Passphrase != "pass-2" {
		t.Errorf("WithPassphrase did not override passphrase: got %q, want %q", kg.Passphrase, "pass-2")
	}

	gotK := kwpo.Bytes()
	// pass-2 should override pass-1
	if !reflect.DeepEqual(gotK, k2) {
		t.Errorf("NewAesKey(%q, WithPassphrase(%q)) did not override passphrase effect: got %x, want %x", "pass-1", "pass-2", gotK, k2)
	}
}

// derive a key from a passphrase, with the default provider settings.
func ExampleNewKey() {
	passphrase := "my-secret-key"
	keyLen := Aes256 // 32
	salt := "NaCl"

	key := NewKey(passphrase, keyLen, salt)

	// use the key for encryption or any other purpose
	_ = key
}

// derive a key from a passphrase, with custom provider settings.
func ExampleProvider_NewKey() {
	sc := NewProvider(
		WithKeyDerivation(kdf.RecommendedArgon2id()),
	)

	passphrase := "my-secret-key"
	keyLen := Aes256 // 32
	salt := "NaCl"

	key := sc.NewKey(passphrase, keyLen, salt)

	// use the key for encryption or any other purpose
	_ = key
}
