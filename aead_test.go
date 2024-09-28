package simplecipher

import (
	"testing"
)

func FuzzNewGCM(f *testing.F) {
	// key: bytes, nonce: bytes, plaintext: string
	f.Add([]byte("key0key1key2key3"), []byte("nonce0nonce1"), "plain-text-plain-text000")
	f.Add([]byte("key0key1key2key3key4key5key6key7"), []byte("nonce0nonce1"), "plain-text-plain")

	f.Fuzz(func(t *testing.T, key, nonce []byte, plaintext string) {
		createGCM := func() Cipher {
			return NewGCM(Bytes(key), Bytes(nonce))
		}

		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			testErrorCipher("badKeyLen", t, createGCM, plaintext)
			return
		}
		if len(nonce) != 12 {
			testErrorCipher("badNonceLen", t, createGCM, plaintext)
			return
		}

		testCipher("", t, createGCM, plaintext)
	})
}

func FuzzSimpleGCM(f *testing.F) {
	// key: string, nonce: string, plaintext: string
	f.Add("key", "nonce", "plaintext")

	f.Fuzz(func(t *testing.T, key, nonce, plaintext string) {
		createSimpleGCM := func() Cipher {
			return SimpleGCM(key, nonce)
		}

		testCipher("", t, createSimpleGCM, plaintext)
	})
}
