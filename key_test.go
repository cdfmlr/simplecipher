package simplecipher

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestBytes_Bytes(t *testing.T) {
	DefaultSalt = func() string { return "testsalt" }

	tests := []struct {
		name string
		k    Bytes
		want []byte
	}{
		{
			name: "empty",
			k:    Bytes{},
			want: []byte{},
		},
		{
			name: "nil",
			k:    Bytes(nil),
			want: nil,
		},
		{
			name: "common",
			k:    Bytes{1, 2, 3},
			want: []byte{1, 2, 3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.k.Bytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Bytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_keyGen_Bytes(t *testing.T) {
	DefaultSalt = func() string { return "testsalt" }

	type fields struct {
		Passphrase string
		Len        KeyLen
		Salt       string
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
			},
			want: "",
		},
		{
			name: "lessThanZero",
			fields: fields{
				Passphrase: "any",
				Len:        -1,
				Salt:       "",
			},
			want: "",
		},
		{
			name: "aes128",
			fields: fields{
				Passphrase: "hello, world",
				Len:        Aes128,
				Salt:       "testsalt",
			},
			want: "4f1db40b0cd47e1d2639da8c95ef6d1b",
		},
		{
			name: "aes192",
			fields: fields{
				Passphrase: "hello, world",
				Len:        Aes192,
				Salt:       "testsalt",
			},
			want: "4f1db40b0cd47e1d2639da8c95ef6d1b65e706e6e211680e",
		},
		{
			name: "aes256",
			fields: fields{
				Passphrase: "hello, world",
				Len:        Aes256,
				Salt:       "testsalt",
			},
			want: "4f1db40b0cd47e1d2639da8c95ef6d1b65e706e6e211680eeb14dc23ce8de545",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := keyGen{
				Passphrase: tt.fields.Passphrase,
				Len:        tt.fields.Len,
				Salt:       tt.fields.Salt,
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
	DefaultSalt = func() string { return "testsalt" }

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
			kg := NewAesKey(tt.args.passphrase, tt.args.options...)
			got := kg.Bytes()
			gotHex := hex.EncodeToString(got)

			if !reflect.DeepEqual(gotHex, tt.wantBytes) {
				t.Errorf("NewAesKey().Bytes() = %v, want %v", gotHex, tt.wantBytes)
			}
		})
	}
}

func TestNewNonce(t *testing.T) {
	DefaultSalt = func() string { return "testsalt" }

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
			kg := NewNonce(tt.args.passphrase, tt.args.options...)
			got := kg.Bytes()
			gotHex := hex.EncodeToString(got)

			if !reflect.DeepEqual(gotHex, tt.wantBytes) {
				t.Errorf("NewNonce().Bytes() = %v, want %v", gotHex, tt.wantBytes)
			}
		})
	}
}

func TestNewIv(t *testing.T) {
	DefaultSalt = func() string { return "testsalt" }

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
			kg := NewIv(tt.args.passphrase, tt.args.options...)
			got := kg.Bytes()
			gotHex := hex.EncodeToString(got)

			if !reflect.DeepEqual(gotHex, tt.wantBytes) {
				t.Errorf("NewNonce().Bytes() = %v, want %v", gotHex, tt.wantBytes)
			}
		})
	}
}

func TestNewRandomIv(t *testing.T) {
	DefaultSalt = func() string { return "testsalt" }

	iv1 := NewRandomIv()
	iv2 := NewRandomIv()

	if reflect.DeepEqual(iv1.Bytes(), iv2.Bytes()) {
		t.Errorf("NewRandomIv() = %v, want random", iv1.Bytes())
	}
	// t.Logf("iv1: %x, iv2: %x", iv1.Bytes(), iv2.Bytes())
}
